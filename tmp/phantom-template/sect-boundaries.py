from docx import Document
from docx.oxml.ns import qn
p=r'D:\Downloads\BCSE497J Project I Report - Template FINAlL Updated  (2).docx'; d=Document(p)
body=d._element.body
for i,c in enumerate(body):
 if c.tag==qn('w:p') and c.pPr is not None and c.pPr.sectPr is not None or c.tag==qn('w:sectPr'):
  print('\nSECTION BREAK AT',i, c.tag)
  for j in range(max(0,i-4),min(len(body),i+4)):
   x=body[j]; print(j,x.tag.split('}')[-1], ''.join(x.itertext())[:100])
for i,s in enumerate(d.sections):
 print('SECTION',i,'footer refs',[(r.get(qn('w:type')),r.get(qn('r:id'))) for r in s._sectPr.findall(qn('w:footerReference'))], 'pgnum', [(x.tag.split('}')[-1],x.attrib) for x in s._sectPr if x.tag.endswith('pgNumType')])
for rel in d.part.rels.values():
 if 'footer' in rel.reltype:
  print(rel.target_part.partname, ''.join(rel.target_part.element.itertext()))
