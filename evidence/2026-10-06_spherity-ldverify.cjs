const path='/Users/abdelrahmanaljabali/Desktop/DPP/dev/backend_dpp/node_modules/';
const jsonld=require(path+'jsonld'); const canonize=require(path+'rdf-canonize');
const crypto=require('crypto'); const fs=require('fs');
const creds=JSON.parse(fs.readFileSync('sph_live.json'));
const cache={};
const loader=async(url)=>{ if(!cache[url]){const r=await fetch(url,{headers:{Accept:'application/ld+json'}}); cache[url]=await r.json();} return {contextUrl:null,documentUrl:url,document:cache[url]}; };
const pub=Buffer.from('7c86199f31fe7a6e1604095eab24aff285e696579a358abd8beebaa57c82c757','hex');
const key=crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),pub]),format:'der',type:'spki'});
async function canon(doc,max){ const ds=await jsonld.toRDF(doc,{documentLoader:loader,safe:false}); return canonize.canonize(ds,{algorithm:'RDFC-1.0',maxDeepIterations:max}); }
(async()=>{
 for(const c of creds){
  const {proof,...doc}=c; const {jws,...opts}=proof; opts['@context']=c['@context'];
  for(const max of [3,Infinity]){
   try{
    const a=await canon(doc,max), b=await canon(opts,max);
    const h=x=>crypto.createHash('sha256').update(x).digest();
    const [hdr,,sig]=jws.split('.');
    const data=Buffer.concat([Buffer.from(hdr+'.'),h(b),h(a)]);
    const ok=crypto.verify(null,data,key,Buffer.from(sig,'base64url'));
    console.log(c.type[1],'max='+max,'sigValid='+ok); break;
   }catch(e){console.log(c.type[1],'max='+max,'ERR',e.message);}
  }
 }
})();
