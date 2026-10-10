"""Analytic sensitivity study for the fixed server source, not an executed server.

Expected values omit per-stage damage rounding, extra hits, effect observers,
healing and cooldowns. Exact probabilities reproduce the 101-outcome roll and
Java float arithmetic; nominal probabilities are an explicitly separate model.
"""
from pathlib import Path
import csv
import json
import math
import struct

ROOT = Path(__file__).resolve().parents[1]

def f32(x):
    return struct.unpack('f', struct.pack('f', x))[0]

def critical_threshold(critical, resist=195, coefficient=1.0, exact=False):
    c = math.floor(f32(f32(critical * f32(coefficient)) - resist) + .5) if exact else math.floor(critical * coefficient - resist + .5)
    if exact:
        first = f32(440 * f32(.1))
        if c <= 440:
            rate = f32(c * f32(.1))
        elif c <= 600:
            rate = f32(first + f32((c - 440) * f32(.05)))
        else:
            rate = f32(f32(first + f32(160 * f32(.05))) + f32((c - 600) * f32(.02)))
    else:
        rate = c * .1 if c <= 440 else 44 + (c - 440) * .05 if c <= 600 else 52 + (c - 600) * .02
    return max(1, rate)

def roll_probability(threshold, exact):
    return max(0, min(101, math.ceil(threshold))) / 101 if exact else min(1, max(0, threshold / 100))

def defense_probability(defense, accuracy, cap, exact):
    # int() truncates toward zero, matching Java integer division.
    threshold = min(cap, max(1, int((defense - accuracy) / 10))) if exact else min(cap, max(1, (defense - accuracy) / 10))
    return roll_probability(threshold, exact)

def expectation(damage=1000, accuracy=2200, critical=598, resist=195,
                evasion=1200, parry=1500, block=2500, shield=True,
                shield_reduction=.7, weapon=True, critical_reduction=0,
                pvp_attack=.10, pvp_defense=.18, uptime=1, exact=False):
    pe = defense_probability(evasion, accuracy, 30, exact)
    pp = defense_probability(parry, accuracy, 40, exact) if weapon else 0
    pb = defense_probability(block, accuracy, 50, exact) if shield else 0
    pc = roll_probability(critical_threshold(critical, resist, exact=exact), exact)
    defense_factor = (1 - pe) * (pp * .6 + (1 - pp) * (1 - pb * shield_reduction))
    critical_factor = 1 + pc * (1.8 * (1 - critical_reduction / 1000) - 1)
    return damage * defense_factor * critical_factor * .6 * (1 + pvp_attack - pvp_defense) * uptime

def generate():
    critical_rows = []
    for resist in (195, 245, 295):
        for critical in (598, 628, 635, 643, 650, 685, 700, 718, 750, 795, 800, 850):
            critical_rows.append({'critical': critical, 'resist': resist,
                                 'effective': critical - resist,
                                 'nominal_threshold': critical_threshold(critical, resist),
                                 'exact_probability_percent': 100 * roll_probability(critical_threshold(critical, resist, exact=True), True)})
    shield_rows = []
    for block in (2500, 2700, 3000):
        for accuracy in range(2000, 3100, 100):
            shield_rows.append({'block': block, 'accuracy': accuracy,
                                'nominal_block_percent': 100 * defense_probability(block, accuracy, 50, False),
                                'exact_block_percent': 100 * defense_probability(block, accuracy, 50, True),
                                'expected_damage_approx': expectation(block=block, accuracy=accuracy),
                                'expected_damage_exact_probability': expectation(block=block, accuracy=accuracy, exact=True)})
    allocations = []
    # Deliberately hypothetical: only these three stone types and ten free slots.
    for shield in (False, True):
        candidates = []
        for n_acc in range(11):
            for n_crit in range(11 - n_acc):
                n_attack = 10 - n_acc - n_crit
                candidates.append({'accuracy_stones': n_acc, 'critical_stones': n_crit, 'attack_stones': n_attack,
                                   'accuracy': 2200 + 25 * n_acc, 'critical': 598 + 15 * n_crit,
                                   'damage_before_avoidance': 1000 + 5 * n_attack,
                                   'expected_damage': expectation(accuracy=2200 + 25 * n_acc, critical=598 + 15 * n_crit,
                                                                  damage=1000 + 5 * n_attack, shield=shield, exact=True)})
        allocations.append({'shield': shield, 'top_five': sorted(candidates, key=lambda x: x['expected_damage'], reverse=True)[:5]})
    verification = {
        'armor_resist_15': 15 * (4 + 3 + 2 + 2 + 2),
        'effective_critical_598': 598 - 195,
        'nominal_598_to_635_gain_percent': 100 * ((1 + .8 * .44) / (1 + .8 * .403) - 1),
        'exact_probability_598_to_635_gain_percent': 100 * ((1 + .8 * 44 / 101) / (1 + .8 * 41 / 101) - 1),
        'checks': []}
    for label, observed, expected in (
        ('crit first knee', critical_threshold(635), 44),
        ('crit second knee', critical_threshold(795), 52),
        ('block upper limit', defense_probability(2500, 1800, 50, True), 50 / 101),
        ('block lower limit', defense_probability(2500, 2500, 50, True), 1 / 101),
        ('block 2500 accuracy 2300', defense_probability(2500, 2300, 50, True), 20 / 101),
        ('Java float crit 403', roll_probability(critical_threshold(598, exact=True), True), 41 / 101),
        ('no shield no block sensitivity', expectation(shield=False, block=2500), expectation(shield=False, block=3000)),
    ):
        assert math.isclose(observed, expected, abs_tol=1e-10), label
        verification['checks'].append({'name': label, 'passed': True})
    out = {'commit': '94fc8048e5fc198f000c0ca2176c65034c57cb39',
           'method': __doc__, 'critical_rows': critical_rows, 'shield_rows': shield_rows,
           'hypothetical_stone_allocation': allocations, 'verification': verification}
    (ROOT / 'analysis/pvp-damage-model.json').write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    for name, rows in (('pvp-critical-thresholds.csv', critical_rows), ('pvp-shield-accuracy.csv', shield_rows)):
        with (ROOT / 'analysis' / name).open('w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    print(json.dumps({'verification': verification, 'illustrative_allocations': allocations}, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    generate()
