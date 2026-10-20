import fs from 'node:fs';
const root='D:/RVE/.codex/local/aion-tw-20261019';
const seeds=JSON.parse(process.argv[3]);
const jobs=[];
for(const [tag,procedure] of seeds) {
  for(const [suffix,name] of [['insns','read_function_instructions'],['pseudo','procedure_pseudo_code'],['callers','procedure_callers']]) jobs.push({file:tag+'-'+suffix,name,arguments:{procedure}});
}
fs.writeFileSync(root+'/jobs-'+process.argv[2]+'.json',JSON.stringify(jobs,null,2));
console.log(JSON.stringify({jobs:jobs.length}));
