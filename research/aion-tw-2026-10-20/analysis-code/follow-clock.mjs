import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import fs from 'node:fs';
const root='D:/RVE/.codex/local/aion-tw-20261019';
const client=new Client({name:'rea-tw-clock-follow',version:'1'});
const transport=new StdioClientTransport({command:'D:/nodejs/node.exe',args:['D:/RVE/scripts/rea.mjs','mcp'],env:{...process.env,REA_IDA_MCP_CONFIG:root+'/ida-mcp.json'},stderr:'pipe'});
transport.stderr?.on('data',()=>{});
const rows=[],seen=new Set();let address='0x1819ff314',reason='bounded experiment ended after 8 additional entries';
try {
  await client.connect(transport);
  const opened=await client.callTool({name:'open_binary',arguments:{path:root+'/samples/Game.dll',provider_id:'ida'}});
  if(opened.isError)throw new Error('REA target open failed');
  for(let i=0;i<8;i++){
    if(seen.has(address)){reason='cycle';break;}seen.add(address);
    const args={procedure:address};
    const result=await client.callTool({name:'read_function_instructions',arguments:args},{timeout:300000});
    const stem=root+'/clock-follow-'+i;
    fs.writeFileSync(stem+'.mcp.json',JSON.stringify({name:'read_function_instructions',arguments:args,result},null,2));
    if(result.structuredContent?.evidence)fs.writeFileSync(stem+'.evidence.json',JSON.stringify({ok:!result.isError,data:result.structuredContent.evidence},null,2));
    const normalized=result.structuredContent?.result;
    if(normalized!==undefined)fs.writeFileSync(stem+'.normalized.json',JSON.stringify(normalized,null,2));
    rows.push({address,isError:result.isError??false,evidence_id:result.structuredContent?.evidence_id??null});
    if(result.isError){reason='provider failure';break;}
    const ins=normalized?.instructions??[];
    console.log(JSON.stringify({address,instructions:ins.length,last:ins.at(-1)}));
    const terminal=ins.at(-1)?.match(/: jmp sub_([0-9A-F]+)$/i);
    if(!terminal){reason='no single named terminal jump in the returned instruction listing';break;}
    address='0x'+terminal[1].toLowerCase();
  }
} finally {
  try {fs.writeFileSync(root+'/clock-follow-close.json',JSON.stringify(await client.callTool({name:'close_binary',arguments:{}}),null,2));}
  finally {await client.close();fs.writeFileSync(root+'/clock-follow-summary.json',JSON.stringify({rows,reason,targetExecuted:false},null,2));}
}
console.log(JSON.stringify({requests:rows.length,reason}));
