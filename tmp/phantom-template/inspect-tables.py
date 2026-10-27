from docx import Document
p=r'D:\project-1\tmp\phantom-template\pandoc-draft.docx'; d=Document(p)
for i,t in enumerate(d.tables):
 print('TABLE',i,'rows',len(t.rows),'cols',len(t.columns))
 for row in t.rows[:3]: print('   '+' | '.join(c.text[:50].replace('\n','/') for c in row.cells))
