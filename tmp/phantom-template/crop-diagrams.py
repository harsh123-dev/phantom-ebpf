from PIL import Image
from pathlib import Path
src=Path(r'D:\project-1\tmp\phantom-template\diagram-source'); out=Path(r'D:\project-1\tmp\phantom-template\diagrams')
def c(page,box,name): Image.open(src/f'page-{page}.png').convert('RGB').crop(box).save(out/name)
c(17,(250,900,1340,1370),'architecture.png')
c(18,(420,90,1240,930),'data-flow.png')
c(19,(255,370,1360,675),'class-diagram.png')
c(19,(260,1020,1340,1450),'sequence.png')
