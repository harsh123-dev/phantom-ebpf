from PIL import Image,ImageDraw
from pathlib import Path
src=Path(r'D:\project-1\tmp\phantom-template\word-pages-01')
fs=sorted(src.glob('page-*.png')); w,h=430,590
for batch in range(2):
 chunk=fs[batch*12:(batch+1)*12]; sheet=Image.new('RGB',(w*3,h*4),'#ddd')
 for i,f in enumerate(chunk):
  im=Image.open(f).convert('RGB'); im.thumbnail((w-16,h-36)); tile=Image.new('RGB',(w,h),'white'); tile.paste(im,((w-im.width)//2,24)); ImageDraw.Draw(tile).text((8,5),f.stem,fill='black'); sheet.paste(tile,((i%3)*w,(i//3)*h))
 sheet.save(src.parent/f'word-contact-{batch+1}.jpg',quality=88)
print('pages',len(fs))
