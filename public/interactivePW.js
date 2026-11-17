(function(){
var BRANDS=["paypal","google","apple","microsoft","amazon","facebook","instagram","netflix","dropbox","linkedin","whatsapp","binance","coinbase","metamask","chase","wellsfargo","bankofamerica","vietcombank","techcombank","momo","zalo","shopee","lazada","dhl","fedex","usps","steam","icloud","outlook","office365"];
var KEYWORDS=["login","signin","verify","secure","account","update","password","confirm","wallet","banking","billing","suspend","unlock","recover","validate","authenticate"];
var BADTLD=["zip","mov","top","xyz","click","link","gq","tk","ml","cf","ga","work","support","rest","country","icu","cam","buzz"];
var SHORT=["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","rb.gy","shorturl.at","tiny.cc"];
var SLD=["co","com","org","net","gov","edu","ac"];
var input=document.getElementById("url"),out=document.getElementById("out");

function regDomain(host){
var p=host.split(".");
if(p.length>=3&&p[p.length-1].length===2&&SLD.indexOf(p[p.length-2])>-1)return p.slice(-3).join(".");
return p.slice(-2).join(".");
}
function deleet(s){return s.replace(/0/g,"o").replace(/1/g,"l").replace(/3/g,"e").replace(/5/g,"s").replace(/rn/g,"m").replace(/vv/g,"w");}

function analyze(raw){
var s=raw.trim(),f=[];
if(!s)return{error:"Enter a link to check."};
var hasScheme=/^[a-z][a-z0-9+.-]*:\/\//i.test(s);
var u;
try{u=new URL(hasScheme?s:"http://"+s);}catch(e){return{error:"That doesn’t look like a valid link. Check it and try again."};}
if(!/^https?:$/.test(u.protocol))return{error:"Only http and https links can be checked."};
var host=u.hostname.toLowerCase(),reg=regDomain(host),labels=host.split("."),tld=labels[labels.length-1];
var name=reg.split(".")[0],full=s.toLowerCase();
function add(w,t,d){f.push({w:w,t:t,d:d});}

if(/^\d{1,3}(\.\d{1,3}){3}$/.test(host)||/^\[.*\]$/.test(host))add(30,"Uses an IP address instead of a name","Real services almost always use a domain name.");
if(hasScheme&&u.protocol==="http:")add(15,"Not encrypted (http)","The connection has no HTTPS, so anything typed can be read in transit.");
if(!hasScheme)add(0,"No scheme given","Checked as http://"+host+"; add https:// if the site uses it.");
if(/@/.test(s.replace(/^[a-z]+:\/\//i,"").split("/")[0]))add(30,"Contains an @ sign before the host","Everything before @ is ignored by the browser, which hides the true destination.");
if(host.indexOf("xn--")>-1||/[^\x00-\x7f]/.test(s))add(25,"Uses look-alike (international) characters","Punycode can imitate well-known names with similar-looking letters.");
if(SHORT.indexOf(host)>-1)add(15,"Link shortener","The real destination is hidden behind a redirect.");
if(labels.length>4)add(15,"Many subdomains ("+labels.length+" parts)","Long chains such as bank.login.verify.example.com are used to hide the real domain.");
if((name.match(/-/g)||[]).length>=2)add(12,"Several hyphens in the domain","Phishing domains often chain words together with hyphens.");
if(BADTLD.indexOf(tld)>-1)add(12,"Domain ending “."+tld+"” is often abused","Cheap or free endings are common in throwaway phishing sites.");
if(s.length>100)add(10,"Very long link ("+s.length+" characters)","Long links can bury the suspicious part.");
if(u.port&&u.port!=="80"&&u.port!=="443")add(12,"Unusual port :"+u.port,"Legitimate sites rarely use a custom port in a link.");
if((s.match(/%[0-9a-f]{2}/gi)||[]).length>=4)add(10,"Heavy percent-encoding","Encoding can disguise what the link really contains.");
if(/https?:\/\/.+https?:\/\//i.test(s)||/[?&](url|redirect|next|goto|return)=https?/i.test(s))add(12,"Contains another web address","Redirect tricks send you on to a different site.");

var kw=KEYWORDS.filter(function(k){return full.indexOf(k)>-1;});
if(kw.length)add(Math.min(8*kw.length,24),"Sensitive words: "+kw.slice(0,4).join(", "),"Words like these are used to make a fake page feel official.");

var hit=null;
for(var i=0;i<BRANDS.length;i++){
var b=BRANDS[i];
if(name===b)continue;
if(host.indexOf(b)>-1){hit={b:b,kind:"inside"};break;}
var d=deleet(name);
if(d!==name&&d.indexOf(b)>-1){hit={b:b,kind:"swap"};break;}
}
if(hit){
if(hit.kind==="inside")add(35,"Mentions “"+hit.b+"” but isn’t "+hit.b+".com","The real domain is "+reg+". Attackers put a brand name in the address to borrow trust.");
else add(40,"Imitates “"+hit.b+"” with swapped characters","“"+name+"” replaces letters with look-alike digits or pairs.");
}
if(!f.some(function(x){return x.w>0;}))add(0,"No common phishing signs found","The domain "+reg+" looks ordinary from its address alone.");
var score=Math.min(100,f.reduce(function(a,x){return a+x.w;},0));
return{score:score,f:f,reg:reg};
}

function esc(t){return String(t).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];});}

function render(r){
if(r.error){out.innerHTML='<p class="err">'+esc(r.error)+'</p>';return;}
var c,v;
if(r.score>=50){c="var(--bad)";v="Likely phishing";}
else if(r.score>=20){c="var(--warn)";v="Suspicious";}
else{c="var(--ok)";v="No warning signs";}
if(r.exact){v="Known phishing site";}
var h='<p class="verdict" style="color:'+c+'">'+v+'</p><p class="score">Risk score '+r.score+' out of 100</p><div class="bar"><i id="fill" style="background:'+c+'"></i></div><ul>';
r.f.forEach(function(x){
var icon=x.w>=25?"✕":x.w>0?"!":"✓";
var ic=x.w>=25?"var(--bad)":x.w>0?"var(--warn)":"var(--ok)";
h+='<li><b style="color:'+ic+'">'+icon+'</b><div>'+esc(x.t)+'<span>'+esc(x.d)+'</span></div></li>';
});
out.innerHTML=h+"</ul>";
requestAnimationFrame(function(){var el=document.getElementById("fill");if(el)el.style.width=Math.max(r.score,3)+"%";});
}

var busy=false;
function run(){
if(busy)return;
var a=analyze(input.value);
if(a.error){render(a);return;}
busy=true;out.innerHTML='<p class="score">Checking blocklists…</p>';
fetch("/api/check?url="+encodeURIComponent(input.value.trim()))
.then(function(r){return r.json().then(function(j){if(!r.ok)throw new Error(j.error||"Lookup failed");return j;});})
.then(function(bl){merge(a,bl);render(a);})
.catch(function(e){a.f.unshift({w:0,t:"Blocklist check unavailable",d:(e&&e.message?e.message:"Could not reach the server")+". Showing link analysis only."});render(a);})
.then(function(){busy=false;});
}
var NAMES={phishtank:"PhishTank",openphish:"OpenPhish",google:"Google Safe Browsing"};
function merge(a,bl){
var items=[],exact=false,host=false;
bl.matches.forEach(function(m){
var who=NAMES[m.source]||m.source;
if(m.type==="exact"){
exact=true;
items.push({w:100,t:"Listed as phishing by "+who,d:(m.target?"Impersonates "+m.target+". ":"")+(m.threats?"Threat type: "+m.threats.join(", ").toLowerCase().replace(/_/g," ")+".":"This exact link was reported and verified.")});
}else{
host=true;
items.push({w:40,t:"Same site listed by "+who,d:"A different page on "+bl.host+" is on the blocklist"+(m.target?" (impersonating "+m.target+")":"")+". The site may be compromised or abused."});
}
});
if(!items.length){
var live=Object.keys(bl.sources).filter(function(k){return bl.sources[k].ok;}).map(function(k){return NAMES[k]||k;});
items.push({w:0,t:live.length?"Not found on "+live.join(", "):"No blocklist could be loaded",d:live.length?"Not being listed only means nobody has reported it yet.":"The server couldn’t download any feed. Check its log."});
}
a.f=items.concat(a.f.filter(function(x){return x.t!=="No common phishing signs found"||!items.length||items[0].w===0;}));
a.score=exact?100:Math.min(100,a.f.reduce(function(t,x){return t+x.w;},0));
a.exact=exact;
}
document.getElementById("go").addEventListener("click",run);
input.addEventListener("keydown",function(e){if(e.key==="Enter")run();});
})();