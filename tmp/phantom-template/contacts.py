from PIL import Image,ImageOps,ImageDraw
from pathlib import Path
src=Path(r'D:\project-1\tmp\phantom-template\template-render')
files=sorted(src.glob('page-*.png'))
thumbs=[]
for f in files:
 im=Image.open(f).convert('RGB'); im.thumbnail((360,510)); canvas=Image.new('RGB',(380,540),'#ddd'); canvas.paste(im,((380-im.width)//2,22)); ImageDraw.Draw(canvas).text((8,4),f.stem,fill='black'); thumbs.append(canvas)
out=Image.new('RGB',(380*4,540*4),'#eee')
for i,im in enumerate(thumbs): out.paste(im,((i%4)*380,(i//4)*540))
out.save(r'D:\project-1\tmp\phantom-template\template-contact.jpg',quality=85)
print('pages',len(files))
