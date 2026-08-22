(()=>{
const node=document.getElementById('clientVersion');if(!node)return;
let rendering=false;
function polishVersion(){if(rendering||node.querySelector('.client-version-release'))return;const text=node.textContent.trim(),match=text.match(/(?:meshlan-nebula\/)?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)\s*·\s*Nebula\s+([^\s]+)/i);if(!match)return;rendering=true;const release=document.createElement('span'),engine=document.createElement('span');release.className='client-version-release';release.textContent='v'+match[1];engine.className='client-version-engine';engine.textContent='Core '+match[2];node.replaceChildren(release,engine);node.title=`MeshLAN ${match[1]} · Nebula ${match[2]}`;rendering=false}
new MutationObserver(polishVersion).observe(node,{childList:true,subtree:true,characterData:true});polishVersion();
})();
