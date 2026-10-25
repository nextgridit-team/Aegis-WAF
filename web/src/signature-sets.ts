import { ruleTabs } from "./rule-tabs";
export type SignatureSet = { id:string; name:string; version:string; digest:string; rule_count:number };
export type ManagedSignatures = {set_id:string;mode:string;paranoia_level:number;inbound_threshold:number;body_limit_bytes:number;excluded_rule_ids:number[]};
export const defaultManagedSignatures = ():ManagedSignatures => ({set_id:"",mode:"off",paranoia_level:1,inbound_threshold:5,body_limit_bytes:65536,excluded_rule_ids:[]});
type Context={api:<T>(path:string,method?:string,body?:unknown)=>Promise<T>;esc:(value:unknown)=>string;heading:(title:string,text:string,buttons?:string)=>string;table:(headers:string[],rows:string[][],label:string)=>string;refresh:()=>Promise<void>;notice:(message:string,error?:boolean)=>void};
export function makeSignatureSetsUI(c:Context){
 let catalogue:{set:SignatureSet;loaded:boolean;engine_version:string}[]=[];
 async function render(){
  const [available,loaded]=await Promise.all([c.api<typeof catalogue>("/signature-sets/catalogue"),c.api<SignatureSet[]>("/signature-sets")]);catalogue=available;
  return c.heading("Rules","Load a versioned signature set, then select it in a protection policy.")+ruleTabs("sets")+
   `<div class="info-panel"><h3>Start in Observe</h3><p>OWASP CRS adds established request signatures through Coraza. Loading a set does not enable it. Policies choose its mode, body limit and targeted rule exclusions. Loaded versions stay unchanged until you explicitly select another version.</p></div>`+
   c.table(["Available set","Version / engine","Rules",""],available.map(item=>[`<strong>${c.esc(item.set.name)}</strong><small>Request headers and bounded request bodies</small>`,`${c.esc(item.set.version)}<small>Coraza ${c.esc(item.engine_version)}</small>`,String(item.set.rule_count),item.loaded?'<span class="badge success">Loaded</span>':`<button class="primary compact" data-action="load-signature-set" data-id="${c.esc(item.set.id)}">Load signature set</button>`]),"Available signature sets")+
   `<section class="section"><div class="section-heading"><h2>Loaded signature sets</h2><a href="#policies">Manage policy assignments</a></div>${loaded.length?c.table(["Set","Version","Checksum"],loaded.map(set=>[`<strong>${c.esc(set.name)}</strong>`,c.esc(set.version),`<code>${c.esc(set.digest.slice(0,12))}</code>`]),"Loaded signature sets"):'<p class="muted">No managed signature sets loaded yet.</p>'}</section>`;
 }
 async function handle(action:string|undefined,id:string){if(action!=="load-signature-set")return false;const item=catalogue.find(item=>item.set.id===id);if(!item)throw new Error("Reload the signature catalogue before loading a set.");await c.api("/signature-sets","POST",{id});await c.refresh();c.notice("Signature set loaded. Select it in a policy to enable inspection.");return true;}
 return {render,handle};
}

export type ManagedSignatureResult = {set_id?:string;version?:string;mode?:string;rule_ids?:number[];matched_count?:number;inspection?:string};
export function managedSignatureSummary(result:ManagedSignatureResult|undefined,esc:(v:unknown)=>string){
 if(!result?.set_id)return "";
 const ids=(result.rule_ids||[]).slice(0,8).map(id=>`#${id}`).join(", ");
 return `<small>OWASP CRS ${esc(result.version)} · ${esc(result.mode)}</small>${ids?`<small>${esc(ids)}${(result.matched_count||0)>8?" …":""}</small>`:""}${result.inspection&&result.inspection!=="complete"?`<small>Inspection: ${esc(result.inspection)}</small>`:""}`;
}
