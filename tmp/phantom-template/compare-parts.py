from zipfile import ZipFile
from pathlib import Path
import hashlib
paths=[r'D:\Downloads\BCSE497J Project I Report - Template FINAlL Updated  (2).docx',r'D:\project-1\tmp\phantom-template\pandoc-draft.docx']
for part in ['word/styles.xml','word/numbering.xml','word/settings.xml','word/header1.xml','word/footer1.xml','word/footer2.xml']:
 vals=[]
 for p in paths:
  with ZipFile(p) as z: vals.append(hashlib.sha256(z.read(part)).hexdigest() if part in z.namelist() else 'missing')
 print(part, vals[0]==vals[1])
