from PIL import Image,ImageDraw,ImageFont
from pathlib import Path
src=Path(r'D:\project-1\tmp\phantom-template\diagram-source')
out=Path(r'D:\project-1\tmp\phantom-template\diagrams'); out.mkdir(exist_ok=True)
# Crops from the compiled source figures (200 dpi)
def crop(page,box,name):
 im=Image.open(src/f'page-{page}.png').convert('RGB')
 im.crop(box).save(out/name)
# actual source image sizes are A4 at 200dpi
for f in src.glob('page-*.png'): print(f.name,Image.open(f).size)
crop(17,(250,720,1320,1065),'architecture.png')
crop(18,(435,95,1175,785),'data-flow.png')
crop(19,(270,365,1065,665),'class-diagram.png')
crop(19,(260,835,1310,1390),'sequence.png')
# clean use-case diagram, preserving the actors and use cases stated in the report
W,H=1800,1080
im=Image.new('RGB',(W,H),'white'); d=ImageDraw.Draw(im)
font_path=r'C:\Windows\Fonts\times.ttf'; bold_path=r'C:\Windows\Fonts\timesbd.ttf'
font=ImageFont.truetype(font_path,42); actor_font=ImageFont.truetype(font_path,38)
# system boundary
left,right,top,bottom=610,1690,80,1000
d.rounded_rectangle((left,top,right,bottom),radius=24,outline='black',width=4)
d.text((left+30,top+20),'PHANTOM services',font=ImageFont.truetype(bold_path,36),fill='black')
# use case ellipses
cases=[(900,230,'Register SBOM\nand image'),(900,430,'Submit runtime\nevent evidence'),(900,640,'Review drift and\ncausal report'),(900,840,'Review PCEPS or\nunavailable status')]
for x,y,label in cases:
 d.ellipse((x-300,y-75,x+300,y+75),outline='black',width=4)
 box=d.multiline_textbbox((0,0),label,font=font,spacing=6,align='center'); tw=box[2]-box[0]; th=box[3]-box[1]
 d.multiline_text((x-tw/2,y-th/2),label,font=font,fill='black',spacing=6,align='center')
# actors (simple stick figures)
def actor(cx,cy,label):
 d.ellipse((cx-34,cy-120,cx+34,cy-52),outline='black',width=4)
 d.line((cx,cy-52,cx,cy+85),fill='black',width=4)
 d.line((cx-75,cy,cx+75,cy),fill='black',width=4)
 d.line((cx,cy+85,cx-65,cy+165),fill='black',width=4)
 d.line((cx,cy+85,cx+65,cy+165),fill='black',width=4)
 box=d.textbbox((0,0),label,font=actor_font); d.text((cx-(box[2]-box[0])/2,cy+180),label,font=actor_font,fill='black')
actor(245,380,'Software operator'); actor(245,780,'Analyst')
# lines connect actors to use cases
for y in [230,430]: d.line((320,380,600,y),fill='black',width=4)
for y in [430,640,840]: d.line((320,780,600,y),fill='black',width=4)
im.save(out/'use-case.png',dpi=(240,240))
print('created',*[p.name for p in out.iterdir()])
