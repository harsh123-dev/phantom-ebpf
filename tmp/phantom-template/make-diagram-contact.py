from PIL import Image,ImageDraw
from pathlib import Path
p=Path(r'D:\project-1\tmp\phantom-template\diagrams'); fs=sorted(p.glob('*.png')); out=Image.new('RGB',(1200,900),'#ddd'); d=ImageDraw.Draw(out); x,y=10,10
for i,f in enumerate(fs):
 im=Image.open(f).convert('RGB'); im.thumbnail((560,360)); d.text((x,y),f.name,fill='black'); out.paste(im,(x,y+20))
 if i%2: x=10; y+=420
 else: x=610
out.save(p/'contact.jpg')
