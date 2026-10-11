'use strict';
const CASE=DATA.cases;
function defenseThreshold(defense,accuracy,cap){return clamp(Math.trunc((defense-accuracy)/10),1,cap);}
function caseRates({a,e,p,b,shield=true,weapon=true,skill=false}){
  const dt=skill?0:defenseThreshold(e,a,30),pt=weapon?defenseThreshold(p,a,40):0,bt=shield?defenseThreshold(b,a,50):0;
  const dodge=dt/101,parry=(1-dodge)*pt/101,block=(1-dodge)*(1-pt/101)*bt/101;
  return {dt,pt,bt,dodge,parry,block,normal:1-dodge-parry-block,conditionalBlock:bt/101};
}
function caseCritical(panel,resist){return probabilityLt(criticalRate(round(f(f(panel)-resist))),100);}
function firstCritGain(panel,resist){const current=caseCritical(panel,resist);for(let c=panel+1;c<=5000;c++)if(caseCritical(c,resist)>current)return c;return null;}
function firstBlockDrop(a,e,p,b,shield){const old=caseRates({a,e,p,b,shield});for(let n=a+1;n<=10000;n++){const next=caseRates({a:n,e,p,b,shield});if(next.block<old.block)return n;}return null;}
function caseSkillValue(skill){const value=Number(skill.effect1_reserved4),delta=Number(skill.effect1_reserved3),learn=CASE.skillLearn.find(x=>x.skillId===skill.id),level=Number(learn.skillLevel);return {value,delta,level,total:value+delta*level,pvp:round(f(f(value+delta*level)*f(Number(skill.pvp_damage_ratio)/100)))};}
function caseSkillEndpoint(w,skillValue){const core=Math.max(1,round(f(f(w*100)*f(.01)))+36+skillValue-round(f(2000*f(.1))));return pvpStage(core,200,100).stage2;}
function renderCases(){
  const weapons=CASE.items.filter(x=>['100900591','101300564'].includes(x.id));
  tableRows('case-weapons',weapons.map(x=>[esc(x._label)+'<br><code>'+x.id+'</code> · 英雄品质 / 50',x.min_damage+'～'+x.max_damage+' / '+x.attack_delay+'ms / '+x.attack_range+'m',x.hit_accuracy+' + '+(x.id==='100900591'?175:140),x.critical+' + '+(x.id==='100900591'?63:78)]));
  const levels=[70,80,90,93,94,100,106,107,110];
  tableRows('case-stones',levels.map(s=>[s+'级',[0,150].map(a=>enchantClient(5,50,s,10,a).display.toFixed(1)+'%').join(' / '),[0,150].map(a=>enchantClient(5,50,s,11,a).display.toFixed(1)+'%').join(' / '),s===94?'低段刚封顶':s===107?'高段刚封顶':s>107?'两个基础段均无额外收益':'仍需区分阶段']));
  chart('case-enchant-chart',{series:[{name:'UI +1～+10，无辅助',color:'#007b78',values:Array.from({length:71},(_,i)=>[i+50,enchantClient(5,50,i+50,10,0).display])},{name:'UI +11～+15，无辅助',color:'#b87718',values:Array.from({length:71},(_,i)=>[i+50,enchantClient(5,50,i+50,11,0).display])}],xmax:120,ymax:100,ticks:[50,70,94,107,120],xlabel:'石头等级'});
  tableRows('case-crit-targets',[0,100,160,240].map(r=>[r,440+r,600+r,pct(caseCritical(600,r))]));
  chart('case-crit-chart',{series:[0,160,240].map((r,i)=>({name:'目标抵抗 '+r,color:['#007b78','#426abb','#b87718'][i],values:Array.from({length:101},(_,j)=>[j*10,caseCritical(j*10,r)*100])})),xmax:1000,ymax:70,ticks:[0,440,600,760,1000],xlabel:'我方单主手致命面板'});
  const accuracy=[1800,1900,2000,2100,2200,2300,2400,2480,2481,2500];
  tableRows('case-accuracy',accuracy.map(a=>{const normal=caseRates({a,e:1600,p:2200,b:2500}),skill=caseRates({a,e:1600,p:2200,b:2500,skill:true});return[a,pct(normal.conditionalBlock), (normal.block*100).toFixed(4),(skill.block*100).toFixed(4),a===1900?'招架少了，格挡事件反增':a===2481?'条件盾防到最低档':a===2000?'仍在盾防上限边界':a===2480?'距离最低档还差1命中':'非实际反击次数'];}));
  tableRows('case-counter-resources',CASE.counterCandidates.map(x=>[esc(x._label)+' / '+x.id,esc(x.counter_skill||'前序连续技')+'<br>chain_skill_prob2='+esc(x.chain_skill_prob2??'缺省'),esc(x._description)]));
  chart('case-block-chart',{series:[{name:'持盾，条件盾防率',color:'#007b78',values:Array.from({length:71},(_,i)=>[i*10,defenseThreshold(2000+i*10,2000,50)/101*100])},{name:'无盾，格挡分支不参与',color:'#b87718',values:[[0,0],[700,0]]}],xmax:700,ymax:50,ticks:[0,200,400,500,700],xlabel:'我的盾防 − 对方命中（对方命中2000）'});
  const skills=CASE.skills.filter(x=>['244','2013','248'].includes(x.id));
  tableRows('case-skills',skills.map(x=>{const s=caseSkillValue(x),learn=CASE.skillLearn.find(z=>z.skillId===x.id);return[esc(x._label)+' / '+x.id+'<br>'+learn.minLevel+'级 / skillLevel='+s.level,esc(x.type)+'；施法字段'+x.casting_delay+'ms<br>'+ (x.id==='248'?'7m / 最多6目标；附加Stumble候选':'单目标；需巨剑/战戟'),s.value+' + '+s.delta+'×'+s.level+' = '+s.total,s.pvp+'（倍率'+x.pvp_damage_ratio+'%）'];}));
  tableRows('case-skill-damage',skills.map(x=>{const s=caseSkillValue(x);return[esc(x._label),...weapons.map(w=>caseSkillEndpoint(Number(w.min_damage),s.pvp)+'～'+caseSkillEndpoint(Number(w.max_damage),s.pvp))];}));
  updateCasePlan();
}
function updateCasePlan(){try{
  const a=num('case-a',0,10000),c=num('case-c',0,5000),r=num('case-r',0,5000),e=num('case-e',0,10000),p=num('case-p',0,10000),b=num('case-b',0,10000),ownB=num('case-own-b',0,10000),enemyA=num('case-enemy-a',0,10000),reduce=num('case-reduce',0,100),shield=$('case-has-shield').value==='1',ownShield=$('case-own-shield').value==='1';
  const q=caseRates({a,e,p,b,shield}),skill=caseRates({a,e,p,b,shield,skill:true}),critical=caseCritical(c,r),next=firstCritGain(c,r),nextBlock=firstBlockDrop(a,e,p,b,shield),own=ownShield?defenseThreshold(ownB,enemyA,50)/101:0;
  $('case-plan').innerHTML='<strong>净致命 '+(c-r)+' → '+pct(critical)+'</strong>；面板拐点 '+(440+r)+' / '+(600+r)+'；下一次抽签收益在 '+(next??'输入范围内已无')+'。<br>普攻：闪避 '+pct(q.dodge)+'，招架 '+pct(q.parry)+'，格挡 '+pct(q.block)+'；物理技能格挡 '+pct(skill.block)+'。<br>条件盾防 '+q.bt+'/101；压到普通最低档的命中目标 '+(shield?Math.max(0,b-19):'对方无盾，无需为盾防加命中')+'；相对当前普攻格挡事件，首次减少在命中 '+(nextBlock??'输入范围内无进一步减少')+'。<br>我方持盾：'+(ownShield?'是；条件盾防 '+pct(own)+'，平均条件减伤 '+pct(own*reduce/100)+'，针对该敌人的封顶盾防 '+(enemyA+500):'否；巨剑/战戟没有普通格挡分支，盾防投资在此分支无收益')+'。<br><span class="minor">格挡机会 ≠ 实际反击次数；当前官方规则、强制状态、窗口刷新未验证。</span>';
  tableRows('case-marginal',[[0,0,'当前'],[100,0,'命中+100'],[0,100,'致命+100']].map(([da,dc,label])=>{const n=caseRates({a:a+da,e,p,b,shield}),s=caseRates({a:a+da,e,p,b,shield,skill:true});return[label,pct(caseCritical(c+dc,r)),(n.block*100).toFixed(4),(s.block*100).toFixed(4)];}));
}catch(error){$('case-plan').textContent=error.message;tableRows('case-marginal',[]);}}
document.querySelectorAll('#cases input,#cases select').forEach(el=>el.addEventListener('input',updateCasePlan));
window.caseAPI={defenseThreshold,caseRates,caseCritical,firstCritGain,firstBlockDrop,caseSkillValue,caseSkillEndpoint};
renderCases();
