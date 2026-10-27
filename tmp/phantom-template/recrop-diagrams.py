from PIL import Image,ImageDraw,ImageFont
from pathlib import Path
src=Path(r'D:\project-1\tmp\phantom-template\diagram-source'); out=Path(r'D:\project-1\tmp\phantom-template\diagrams')
im=Image.open(src/'page-17.png').convert('RGB').crop((250,900,1340,1320)); im.save(out/'architecture.png')
im=Image.open(src/'page-18.png').convert('RGB').crop((420,90,1240,820)); im.save(out/'data-flow.png')
im=Image.open(src/'page-19.png').convert('RGB').crop((255,405,1400,650)); im.save(out/'class-diagram.png')
im=Image.open(src/'page-19.png').convert('RGB').crop((260,1050,1340,1390)); im.save(out/'sequence.png')
# keep use case clean; connect actors to the oval boundary inside the system
f=out/'use-case.png'; im=Image.open(f).convert('RGB'); d=ImageDraw.Draw(im)
# Redraw the association lines over white, then connect them to the left edges of the use-case ellipses.
# Existing actor/case geometry: ellipse left edge x=600; actor hand x=320.
# shift system border/ellipse diagram is still clear; keep current lines that terminate at boundary.
