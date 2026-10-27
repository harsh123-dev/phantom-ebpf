from docx import Document
from docx.oxml.ns import qn
p=r'D:\project-1\tmp\phantom-template\pandoc-draft.docx'; d=Document(p)
for i,e in enumerate(d._element.body):
 tag=e.tag.split('}')[-1]
 text=''.join(e.itertext()).replace('\n','/')[:130]
 if tag=='sectPr': continue
 print(i,tag,repr(text))
