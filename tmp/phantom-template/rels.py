from docx import Document
for lab,p in [('template',r'D:\Downloads\BCSE497J Project I Report - Template FINAlL Updated  (2).docx'),('draft',r'D:\project-1\tmp\phantom-template\pandoc-draft.docx')]:
 d=Document(p); print(lab)
 for k,r in d.part.rels.items():
  print(k,r.reltype.split('/')[-1],r.target_ref)
