/*
 * Evidence-oriented pseudocode, reconstructed manually from this sample.
 * NOT original source; NOT compilable code; NOT an injector or live-memory tool.
 * Game.dll SHA256:
 * 834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786
 * All module-relative constants below are RVAs, not runtime absolute addresses.
 * B = actual module load base (not observed in this offline analysis).
 */

// Game.dll export RVA 0x33A8A0, verified 8-byte function.
CreateGameInstance() {
    return address(B + 0xD647C0); // CXGame static object, NOT *(B + RVA)
}

// Game.dll RVA 0x2B720; CXGame primary vtable slot +0x1E0.
resolve_local_entity() {
    id = u16(B + 0xD6CB08);
    system = ptr(B + 0x94C7B0);
    if (!id || !system) return 0;
    return virtual_call(system, 0x30, id);
}

// Game.dll RVA 0x4F9810; interface identifiers are observed constants.
resolve_game_component(entity) {
    result = 0;
    if (entity && virtual_call(entity, 0xB8)) {
        container = virtual_call(entity, 0xB8);
        virtual_call(container, 0x50, 2, &result);
    }
    return result;
}

// Relevant subset of RVA 0x368E50: the live-component-present branch only.
// Includes additional work not represented here (inventory, names, etc.).
fill_player_snapshot(snapshot) {
    component = resolve_game_component(resolve_local_entity());
    if (component) {
        copy(snapshot, B + 0xD71B78, 0xC8);
        u32(snapshot + 0x40) = max(0, s32(component + 0x119C));
        u32(snapshot + 0x160) = u32(component + 0x22C);
    }
    // A separate no-component branch copies a selected-entry record.
}

// Relevant subset of RVA 0xA2830, only when selector token == "player".
read_player_property(selector) {
    snapshot = initialized_temporary_buffer();
    fill_player_snapshot(snapshot);
    switch (selector) {
        case 0: return u32(snapshot + 0x40);  // UnitHP
        case 1: return u32(snapshot + 0x3C);  // UnitHPMax
        case 2: return u32(snapshot + 0x48);  // UnitMP
        case 3: return u32(snapshot + 0x44);  // UnitMPMax
        case 4: return u32(snapshot + 0xA4);  // UnitClassID; wrapper checks < 12
        case 5: return u16(snapshot + 0x18);  // UnitLevel (zero extended)
        case 6: return u32(snapshot + 0x160); // UnitGender
    }
    // Target, party and summon have different paths and available fields.
}

// ScriptDLL64.dll export RVA 0x6E21B0; use that DLL's load base for S.
GetInterface(input) {
    ptr(S + 0x103F710) = input;
    return address(S + 0xDAE450); // RTTI IScriptDLLImpl, vtable RVA 0xA97118
}
