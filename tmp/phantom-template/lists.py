from docx import Document
from docx.oxml.ns import qn
p=r'D:\project-1\tmp\phantom-template\pandoc-draft.docx'; d=Document(p)
for p in d.paragraphs:
 ppr=p._p.pPr
 if ppr is not None and ppr.find(qn('w:numPr')) is not None: print(p.style.name,repr(p.text))
