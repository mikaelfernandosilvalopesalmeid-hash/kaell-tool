
const $=(s,c=document)=>c.querySelector(s), $$=(s,c=document)=>[...c.querySelectorAll(s)];
const io=new IntersectionObserver(es=>es.forEach(e=>{if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target)}}),{threshold:.12});
$$('.reveal').forEach(el=>io.observe(el));

const chips=$$('.chip'), cards=$$('.article');
chips.forEach(ch=>ch.addEventListener('click',()=>{
  chips.forEach(x=>x.classList.remove('active')); ch.classList.add('active');
  const f=ch.dataset.filter;
  cards.forEach(c=>c.style.display=(f==='Todos'||c.dataset.category===f)?'flex':'none');
}));

const menu=$('.menu');
if(menu) menu.addEventListener('click',()=>{
  const links=$('.links');
  if(!links)return;
  const open=links.dataset.open==='1';
  Object.assign(links.style, open?{}:{display:'flex',position:'absolute',top:'74px',left:'12px',right:'12px',padding:'18px',background:'rgba(5,8,22,.96)',border:'1px solid rgba(146,179,255,.16)',borderRadius:'18px',flexDirection:'column'});
  if(open) links.removeAttribute('style');
  links.dataset.open=open?'0':'1';
});
