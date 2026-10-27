from __future__ import annotations
import re, shutil, zipfile
from copy import deepcopy
from pathlib import Path
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.text.paragraph import Paragraph
from docx.table import Table

TEMPLATE = Path(r"D:\Downloads\BCSE497J Project I Report - Template FINAlL Updated  (2).docx")
DRAFT = Path(r"D:\project-1\tmp\phantom-template\pandoc-draft.docx")
TEX = Path(r"D:\project-1\output\PHANTOM_Project_Report_LaTeX\main.tex")
LOGO = Path(r"D:\project-1\output\PHANTOM_Project_Report_LaTeX\vit-logo.png")
DIAGRAMS = Path(r"D:\project-1\tmp\phantom-template\diagrams")
OUT = Path(r"D:\project-1\output\PHANTOM_Project_Report_Word\PHANTOM_Project_Report_Final.docx")

# Start from the retained template document so its sections, page numbering,
# headers, footers, and theme remain the package foundation.
base = Document(str(TEMPLATE))
section_nodes = [deepcopy(s._sectPr) for s in base.sections]
source = Document(str(DRAFT))

# Add only styles introduced by Pandoc and not present in the template.
base_style_ids = {s.style_id for s in base.styles}
for style_el in source.styles.element:
    if style_el.tag == qn('w:style'):
        sid = style_el.get(qn('w:styleId'))
        if sid and sid not in base_style_ids:
            base.styles.element.append(deepcopy(style_el))
            base_style_ids.add(sid)

# Remap external hyperlink relationship IDs from the converted content into
# the template package. (The supplied template itself is never modified.)
rel_map = {}
for rel in source.part.rels.values():
    if rel.is_external:
        rel_map[rel.rId] = base.part.relate_to(rel.target_ref, rel.reltype, is_external=True)

# Helpers for DOCX XML editing.
def set_paragraph_text(p: Paragraph, text: str):
    for child in list(p._p):
        if child.tag != qn('w:pPr'):
            p._p.remove(child)
    if text:
        p.add_run(text)

def add_after(p: Paragraph, text='', style=None) -> Paragraph:
    el = OxmlElement('w:p')
    p._p.addnext(el)
    newp = Paragraph(el, p._parent)
    if style:
        newp.style = style
    if text:
        newp.add_run(text)
    return newp

def add_before(p: Paragraph, text='', style=None) -> Paragraph:
    el = OxmlElement('w:p')
    p._p.addprevious(el)
    newp = Paragraph(el, p._parent)
    if style:
        newp.style = style
    if text:
        newp.add_run(text)
    return newp

def add_field(p: Paragraph, instruction: str, cached=''):
    fld = OxmlElement('w:fldSimple')
    fld.set(qn('w:instr'), instruction)
    r = OxmlElement('w:r')
    t = OxmlElement('w:t')
    t.text = cached
    r.append(t); fld.append(r); p._p.append(fld)

def clear_numpr(p: Paragraph):
    ppr = p._p.get_or_add_pPr()
    numpr = ppr.find(qn('w:numPr'))
    if numpr is not None:
        ppr.remove(numpr)

def set_seq_caption(p: Paragraph, label: str, chapter: int, n: int, title: str):
    set_paragraph_text(p, '')
    p.style = 'Normal'
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = (label == 'Table')
    p.paragraph_format.keep_together = True
    lab=p.add_run(f'{label} {chapter}.'); lab.bold=True; lab.font.size=Pt(10)
    fld = OxmlElement('w:fldSimple')
    fld.set(qn('w:instr'), f'SEQ {label} \\r {n}')
    r = OxmlElement('w:r'); t = OxmlElement('w:t'); t.text = str(n); r.append(t); fld.append(r)
    p._p.append(fld)
    tail=p.add_run(f': {title}'); tail.font.size=Pt(10)

# Drop unused zero-row tables created for unsupported float/contents commands.
for t in list(source.tables):
    if len(t.rows) == 0:
        t._element.getparent().remove(t._element)

# Remove the spurious 1.15 inserted by the LaTeX preamble parser.
for p in source.paragraphs:
    if p.text.startswith('1.15 '):
        set_paragraph_text(p, p.text[5:])

# Repair text lost by LaTeX-to-Word conversion and retain the implemented formulas.
for p in source.paragraphs:
    if p.text.startswith('For candidate order'):
        set_paragraph_text(p,
            'For candidate order k, the Laplace-smoothed transition estimate is '
            'p̂_k(x|h) = (n_k(h,x) + 1) / (n_k(h) + |Σ|). '
            'Model selection minimizes BIC(k) = −2 log L_k + q_k log N, where '
            'q_k = |H_k| (|Σ| − 1). Contexts are pruned when local BIC does not '
            'improve on a retained suffix. For an observed window, the weighted '
            'conditional divergence is shown below.')
    elif p.text.startswith('This is a numerical score in nats'):
        set_paragraph_text(p,
            'This is a numerical score in nats, not a calibrated anomaly probability. '
            'The scorer does not implement the proposed split-conformal alert threshold. '
            'BDG edge weights are updated as wₑ(t) = λ^((t − t_prev)/Δ) '
            'wₑ(t_prev) + qₑ. The fixed semantic causal tiers are assumptions, not proof of cause.')
    elif p.text.startswith('All six completed runs have a recorded drift event'):
        set_paragraph_text(p,
            'All six completed runs have a recorded drift event. The event-positive fraction '
            'is 6/6 = 1.000 (100%), with a two-sided 95% Wilson score interval of '
            '[0.610, 1.000]. This is not a validated recall estimate. Latency is measured '
            'from injection timestamp to the first recorded PHANTOM event timestamp; '
            'P95 uses linear interpolation.')

# Remove the duplicate repeated header row from the long modules table.
if len(source.tables) > 7 and len(source.tables[7].rows) > 1:
    first=[c.text.strip() for c in source.tables[7].rows[0].cells]
    second=[c.text.strip() for c in source.tables[7].rows[1].cells]
    if first==second and first and first[0]=='Module':
        source.tables[7]._tbl.remove(source.tables[7].rows[1]._tr)

# Repair the symbols whose math syntax was dropped by the converter.
if len(source.tables) > 3:
    symbols = source.tables[3]
    values = [
        ('G=(V,E)', 'Typed Behavioral Dependency Graph'),
        ('Sigma', 'Behavioral token alphabet'),
        ('h', 'Markov context'),
        ('N', 'Number of training tokens'),
        ('K_max', 'Maximum candidate model order'),
        ('D_KL', 'Conditional divergence score, in nats'),
        ('lambda, Delta', 'BDG decay parameter and time scale'),
        ('q_e', 'Incremental edge-evidence weight'),
        ('S, D, X', 'Candidate treatment, drift outcome, and covariates'),
    ]
    while len(symbols.rows) < len(values):
        symbols.add_row()
    for row, (a, b) in zip(symbols.rows, values):
        row.cells[0].text = a; row.cells[1].text = b

# Alphabetize abbreviations in accordance with the template note.
if len(source.tables) > 2:
    ab = source.tables[2]
    rows = list(ab.rows)
    if rows:
        header = [c.text for c in rows[0].cells]
        data = [[c.text for c in r.cells] for r in rows[1:]]
        data.sort(key=lambda x: x[0].casefold())
        for row in list(ab.rows)[1:]:
            for c in row.cells: c.text = ''
        for idx, vals in enumerate(data, 1):
            if idx >= len(ab.rows): ab.add_row()
            for cell, val in zip(ab.rows[idx].cells, vals): cell.text = val

# Repair the cover author table generated from the source's author metadata.
cover_table = source.tables[0]
while len(cover_table.rows) > 3:
    cover_table._tbl.remove(cover_table.rows[-1]._tr)
cover_table.rows[0].cells[0].text = 'Register Number'
cover_table.rows[0].cells[1].text = 'Student Name and Email'
cover_people = [
    ('23BDS0078', 'HARSH RANJAN', 'harsh.ranjan2023@vitstudent.ac.in'),
    ('23BDS0191', 'JAI GOEL', 'jai.goel2023@vitstudent.ac.in'),
]
for i,(reg,name,email) in enumerate(cover_people,1):
    cover_table.rows[i].cells[0].text=reg
    c=cover_table.rows[i].cells[1]; c.text=''
    p=c.paragraphs[0]; p.add_run(name).bold=True
    p.add_run('\n'+email)
cover_table.alignment=WD_TABLE_ALIGNMENT.CENTER
cover_table.autofit=False
for row in cover_table.rows:
    row.cells[0].width=Inches(1.8); row.cells[1].width=Inches(3.3)
    for cell in row.cells:
        cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
        for p in cell.paragraphs:
            p.paragraph_format.space_after=Pt(1)
            for run in p.runs:
                run.font.name='Times New Roman'; run.font.size=Pt(10 if '@' in run.text else 12)
# Remove borders from the student block to follow the cover's open table treatment.
tblPr=cover_table._tbl.tblPr
borders=tblPr.find(qn('w:tblBorders'))
if borders is None:
    borders=OxmlElement('w:tblBorders'); tblPr.append(borders)
for edge in ('top','left','bottom','right','insideH','insideV'):
    el=borders.find(qn('w:'+edge))
    if el is None: el=OxmlElement('w:'+edge); borders.append(el)
    el.set(qn('w:val'),'nil')

# Add the campus-program label and template-required cover wording.
ps=list(source.paragraphs)
if ps and ps[0].text.startswith('PHANTOM:'):
    title=ps[0]
    first=add_before(title,'B.Tech. BCSE497J - Project-I','Normal')
    first.alignment=WD_ALIGN_PARAGRAPH.CENTER
    first.paragraph_format.space_after=Pt(22)
    for r in first.runs: r.bold=True; r.font.name='Times New Roman'; r.font.size=Pt(14)
    title.style='Normal'; title.alignment=WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.space_after=Pt(26); title.paragraph_format.line_spacing=1.5
    for r in title.runs: r.bold=True; r.font.name='Times New Roman'; r.font.size=Pt(18); r.all_caps=True
# Center cover text and insert “by” between degree text and authors table.
for p in source.paragraphs[:4]:
    if p.text.startswith('Submitted in partial') or p.text.startswith('Bachelor of Technology') or p.text.startswith('Under the Supervision'):
        p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after=Pt(8)
# Insert "by" immediately before the author table (after the degree paragraph).
body=list(source._element.body)
table_el=cover_table._tbl
previous=table_el.getprevious()
if previous is not None and previous.tag==qn('w:p'):
    prev=Paragraph(previous, source._body)
    by=add_after(prev,'by','Normal'); by.alignment=WD_ALIGN_PARAGRAPH.CENTER

# Add the missing contents and figure/table list pages after acknowledgements.
ack_sign = next((p for p in source.paragraphs if p.text.strip().replace('\n',' ') in ('Harsh Ranjan Jai Goel','Harsh Ranjan  Jai Goel')), None)
if ack_sign is None:
    ack_sign = next((p for p in source.paragraphs if 'Harsh Ranjan' in p.text and 'Jai Goel' in p.text and p.style.name=='Body Text'), None)
if ack_sign is None:
    raise RuntimeError('Could not find acknowledgements signature slot')

def add_index_page(after, title, instr, break_before=False):
    h=add_after(after,title,'Normal'); h.alignment=WD_ALIGN_PARAGRAPH.CENTER
    h.paragraph_format.page_break_before=break_before
    h.paragraph_format.keep_with_next=True
    for r in h.runs: r.bold=True; r.font.name='Times New Roman'; r.font.size=Pt(14)
    f=add_after(h,'','Normal'); f.paragraph_format.line_spacing=1.15
    add_field(f,instr,'(Update this field in Word if the list is not refreshed automatically.)')
    f.paragraph_format.space_after=Pt(0)
    return f
cursor=add_index_page(ack_sign,'TABLE OF CONTENTS','TOC \\o "1-3" \\h \\z \\u',True)
cursor=add_index_page(cursor,'LIST OF FIGURES','TOC \\h \\z \\c "Figure"',True)
cursor=add_index_page(cursor,'LIST OF TABLES','TOC \\h \\z \\c "Table"',True)

# Ensure preliminary pages follow the provided template's one-page sequence.
front_page_heads={'Declaration','Certificate','Acknowledgements','List of Abbreviations','Symbols and Notations','Abstract'}
for p in source.paragraphs:
    if p.text.strip() in front_page_heads:
        p.paragraph_format.page_break_before=True
        p.paragraph_format.keep_with_next=True
        p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        set_paragraph_text(p,p.text.strip().upper())

# Add actual chapter labels, section numbering, and template-style hierarchy.
chapters={
 'Introduction':(1,'INTRODUCTION'),
 'Project Description and Goals':(2,'PROJECT DESCRIPTION AND GOALS'),
 'Technical Specification':(3,'TECHNICAL SPECIFICATION'),
 'Design Approach and Details':(4,'DESIGN APPROACH AND DETAILS'),
 'Methodology and Testing':(5,'METHODOLOGY AND TESTING'),
 'Project Demonstration':(6,'PROJECT DEMONSTRATION'),
 'Result and Discussion':(7,'RESULT AND DISCUSSION'),
 'Conclusion':(8,'CONCLUSION'),
}
# Transform original chapter title paragraphs into CHAPTER N, then add the title line.
for p in list(source.paragraphs):
    if p.style.name=='Heading 1' and p.text.strip() in chapters:
        n,label=chapters[p.text.strip()]
        set_paragraph_text(p,f'CHAPTER {n}')
        p.style='Heading 1'; p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.keep_with_next=True
        p.paragraph_format.page_break_before=(n>1)
        h=add_after(p,f'{n}. {label}','Heading 2')
        h.alignment=WD_ALIGN_PARAGRAPH.CENTER; h.paragraph_format.keep_with_next=True
# Appendices: reformat appendix heading and add title line.
for p in list(source.paragraphs):
    if p.style.name=='Heading 1' and p.text.strip()=='Algorithm and Reproducibility Checklist':
        set_paragraph_text(p,'APPENDIX A'); p.style='Heading 1'; p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.page_break_before=True; p.paragraph_format.keep_with_next=True
        h=add_after(p,'A. ALGORITHM AND REPRODUCIBILITY CHECKLIST','Heading 2')
        h.alignment=WD_ALIGN_PARAGRAPH.CENTER; h.paragraph_format.keep_with_next=True
    elif p.style.name=='Heading 2' and p.text.strip()=='Evidence-Gated Processing':
        set_paragraph_text(p,'A.1 Evidence-Gated Processing'); p.style='Heading 3'
    elif p.style.name=='Heading 2' and p.text.strip()=='Reproducibility Checklist':
        set_paragraph_text(p,'A.2 Reproducibility Checklist'); p.style='Heading 3'

# Number the chapter sections and nested sections with the template's three-level hierarchy.
current_chapter=None; sec=0; sub=0
chapter_start_re=re.compile(r'^CHAPTER (\d+)$')
for p in list(source.paragraphs):
    m=chapter_start_re.match(p.text.strip())
    if m:
        current_chapter=int(m.group(1)); sec=0; sub=0; continue
    if p.text.strip()=='APPENDIX A':
        current_chapter=None; sec=0; sub=0; continue
    if p.text.strip().startswith(('A.1 ', 'A.2 ')):
        continue
    if current_chapter and p.style.name in ('Heading 2','Heading 3'):
        text=p.text.strip()
        title_re=re.match(rf'^{current_chapter}\.\s+',text)
        if title_re: # inserted chapter-title paragraph
            continue
        if p.style.name=='Heading 2':
            sec+=1; sub=0
            set_paragraph_text(p,f'{current_chapter}.{sec} {text}')
            p.style='Heading 3'
        else:
            if sec==0: sec=1
            sub+=1
            set_paragraph_text(p,f'{current_chapter}.{sec}.{sub} {text}')
            p.style='Heading 3'
# Keep chapter and section headings with their first paragraph.
for p in source.paragraphs:
    if p.style.name in ('Heading 1','Heading 2','Heading 3'):
        p.paragraph_format.keep_with_next=True

# Turn the one flattened bibliography paragraph into the verified 30 IEEE entries.
tex=TEX.read_text(encoding='utf-8')
ref_match=re.search(r'\\begin\{thebibliography\}.*?\\end\{thebibliography\}',tex,re.S)
if not ref_match: raise RuntimeError('Bibliography not found in source paper')
ref_block=ref_match.group(0)
ref_raw=re.findall(r'\\bibitem\{r(\d+)\}\s*(.*?)(?=\\bibitem\{|\\end\{thebibliography\})',ref_block,re.S)
def latex_plain(s):
    s=s.strip()
    s=re.sub(r'\\url\{([^}]*)\}',r'\1',s)
    for cmd in ('emph','textit','textbf','texttt'):
        s=re.sub(r'\\'+cmd+r'\{([^}]*)\}',r'\1',s)
    s=s.replace('\\&','&').replace('\\_','_').replace('\\%','%')
    s=s.replace('``','“').replace("''",'”').replace('--','–')
    s=re.sub(r'\\[a-zA-Z]+\*?', '', s)
    s=s.replace('{','').replace('}','')
    return re.sub(r'\s+',' ',s).strip()
refs=[f'[{n}] {latex_plain(text)}' for n,text in ref_raw]
# Delete pandoc's empty bibliography label and flattened references paragraph.
for p in list(source.paragraphs):
    tx=p.text.strip()
    if tx=='99' or tx.startswith('CISA, “Reported Supply Chain Compromise'):
        p._p.getparent().remove(p._p)
# Add References chapter before Appendix A.
appendix=next((p for p in source.paragraphs if p.text.strip()=='APPENDIX A'),None)
if appendix is None: raise RuntimeError('Appendix heading not found')
refh1=add_before(appendix,'CHAPTER 9','Heading 1')
refh1.alignment=WD_ALIGN_PARAGRAPH.CENTER; refh1.paragraph_format.keep_with_next=True
refh2=add_after(refh1,'9. REFERENCES','Heading 2')
refh2.alignment=WD_ALIGN_PARAGRAPH.CENTER; refh2.paragraph_format.keep_with_next=True
cursor=refh2
for text in refs:
    cursor=add_after(cursor,text,'List Paragraph')
    cursor.paragraph_format.left_indent=Inches(0.30)
    cursor.paragraph_format.first_line_indent=Inches(-0.30)
    cursor.paragraph_format.space_after=Pt(4)
    cursor.paragraph_format.line_spacing=1.0

# Convert list paragraphs from imported numbering XML to explicit numbered text.
list_context=''; counts={}
for p in list(source.paragraphs):
    if p.style.name.startswith('Heading'):
        list_context=p.text
    if p._p.pPr is not None and p._p.pPr.find(qn('w:numPr')) is not None:
        if list_context.endswith('Objectives'):
            key='objectives'; counts[key]=counts.get(key,0)+1; prefix=f'{counts[key]}. '
        elif list_context.endswith('Data Flow Diagram'):
            key='flow'; counts[key]=counts.get(key,0)+1; prefix=f'{counts[key]}. '
        else:
            key='check'; counts[key]=counts.get(key,0)+1; prefix='- '
        clear_numpr(p); set_paragraph_text(p,prefix+p.text)
        p.paragraph_format.left_indent=Inches(0.25)
        p.paragraph_format.first_line_indent=Inches(-0.2)

# Rebuild figure/table captions as numbered Word SEQ fields and record image slots.
figs={
 'Logical service architecture from repository modules':(4,1,'architecture.png',5.4),
 'Data flow and evidence gates':(4,2,'data-flow.png',3.6),
 'Primary project use cases':(4,3,'use-case.png',5.4),
 'Conceptual entity relationships':(4,4,'class-diagram.png',5.4),
 'Simplified report-generation sequence':(4,5,'sequence.png',5.4),
}
tables={
 'Project work status':(2,1),
 'Environment facts in the repository':(3,1),
 'Main use cases':(4,1),
 'Repository modules and status':(5,1),
 'Run-level observed outcomes':(7,1),
 'Injection-to-first-recorded-event latency':(7,2),
}
for p in list(source.paragraphs):
    text=p.text.strip()
    matched=False
    for cap,(chap,num,img,width) in figs.items():
        if text==cap:
            set_seq_caption(p,'Figure',chap,num,cap)
            p._p.set('data-figure',f'{chap}.{num}') # harmless custom marker removed below
            matched=True; break
    if matched: continue
    for cap,(chap,num) in tables.items():
        if text==cap:
            set_seq_caption(p,'Table',chap,num,cap)
            matched=True; break

# Clean stray custom attributes; image paragraphs are inserted after body copy.
for el in source._element.body.iter():
    if 'data-figure' in el.attrib: del el.attrib['data-figure']

# Copy the edited content into the retained template package, preserving its
# original template parts and placing the four original section definitions.
target_body=base._element.body
for child in list(target_body):
    if child.tag != qn('w:sectPr'):
        target_body.remove(child)
# Replace final section properties with the original final section properties.
old_final=target_body.find(qn('w:sectPr'))
if old_final is None: raise RuntimeError('Template final section properties missing')
old_final.getparent().replace(old_final,deepcopy(section_nodes[3]))

# Insert copied paragraphs/tables in their existing order. Strip empty bookmarks
# and remap external links to the template package's relationship ids.
source_children=[c for c in source._element.body if c.tag in (qn('w:p'),qn('w:tbl'))]
for child in source_children:
    clone=deepcopy(child)
    for e in clone.iter():
        for attr in (qn('r:id'),qn('r:embed'),qn('r:link')):
            val=e.get(attr)
            if val in rel_map: e.set(attr,rel_map[val])
        if e.tag in (qn('w:bookmarkStart'),qn('w:bookmarkEnd')):
            parent=e.getparent()
            if parent is not None: parent.remove(e)
    target_body.insert(len(target_body)-1,clone)

# Add the requested logo/date to the copied title page.
body_children=list(target_body)
body_paras=[Paragraph(x,base._body) for x in body_children if x.tag==qn('w:p')]
guide=next((p for p in body_paras if 'Dr. THANUJA R' in p.text and 'School of Computer Science and Engineering' in p.text),None)
if guide is None: raise RuntimeError('Cover guide block not found')
if 'image' in guide.text:
    set_paragraph_text(guide, guide.text.replace('image','').strip())
guide_text=guide.text.replace('Dr. THANUJA R\nthanuja.r@',
                              'Dr. THANUJA R\nAssociate Professor Grade 1\nthanuja.r@')
set_paragraph_text(guide,guide_text)
guide.alignment=WD_ALIGN_PARAGRAPH.CENTER
guide.paragraph_format.line_spacing=1.15
guide.paragraph_format.space_after=Pt(4)
logo_p=add_after(guide,'','Normal'); logo_p.alignment=WD_ALIGN_PARAGRAPH.CENTER
logo_p.paragraph_format.space_before=Pt(10); logo_p.paragraph_format.space_after=Pt(0)
logo_p.add_run().add_picture(str(LOGO),width=Inches(2.7))
date_p=add_after(logo_p,'October 2026','Normal'); date_p.alignment=WD_ALIGN_PARAGRAPH.CENTER
# End cover section at the date paragraph.
def put_sectpr(p, secpr):
    ppr=p._p.get_or_add_pPr()
    existing=ppr.find(qn('w:sectPr'))
    if existing is not None: ppr.remove(existing)
    ppr.append(deepcopy(secpr))
put_sectpr(date_p,section_nodes[0])

# End the front-matter section after abstract keywords; reset main text to Arabic 1.
body_paras=[Paragraph(x,base._body) for x in target_body if x.tag==qn('w:p')]
keywords=next((p for p in body_paras if p.text.strip().startswith('Keywords:')),None)
if keywords is None: raise RuntimeError('Abstract keywords paragraph missing')
put_sectpr(keywords,section_nodes[1])
# Chapter 1 begins on the next page as section 2. The References section starts
# on a new page while retaining the Arabic page sequence.
conclusion_body=None
for i,p in enumerate(body_paras):
    if p.text.strip()=='CHAPTER 8':
        for q in body_paras[i+1:]:
            if q.style.name not in ('Heading 1','Heading 2','Heading 3') and q.text.strip():
                conclusion_body=q; break
        break
if conclusion_body is None: raise RuntimeError('Conclusion body paragraph missing')
put_sectpr(conclusion_body,section_nodes[2])

# Put page breaks on template's separate preliminary and chapter pages.
for p in [Paragraph(x,base._body) for x in target_body if x.tag==qn('w:p')]:
    if p.text.strip() in {'Certificate','Acknowledgements','List of Abbreviations','Symbols and Notations','Abstract'}:
        p.paragraph_format.page_break_before=True
    if p.text.strip() in {f'CHAPTER {i}' for i in range(2,9)} or p.text.strip()=='APPENDIX A':
        p.paragraph_format.page_break_before=True
    if p.style.name in ('Heading 1','Heading 2','Heading 3'):
        p.paragraph_format.keep_with_next=True

# Apply the template's readable report spacing consistently while preserving
# compact reference entries and captions.
base.styles['Normal'].paragraph_format.line_spacing=1.15
base.styles['Normal'].paragraph_format.space_after=Pt(0)
base.styles['Body Text'].paragraph_format.line_spacing=1.15
base.styles['Body Text'].paragraph_format.space_after=Pt(0)
base.styles['List Paragraph'].paragraph_format.line_spacing=1.15
base.styles['List Paragraph'].paragraph_format.space_after=Pt(0)
base.styles['Heading 1'].paragraph_format.space_before=Pt(0)
base.styles['Heading 1'].paragraph_format.space_after=Pt(8)
base.styles['Heading 2'].paragraph_format.space_before=Pt(10)
base.styles['Heading 2'].paragraph_format.space_after=Pt(6)
base.styles['Heading 3'].paragraph_format.space_before=Pt(8)
base.styles['Heading 3'].paragraph_format.space_after=Pt(4)
for p in [Paragraph(x,base._body) for x in target_body if x.tag==qn('w:p')]:
    tx=p.text.strip()
    if tx.startswith('Place: Vellore Date:'):
        set_paragraph_text(p,'Place: Vellore\nDate: October 2026')
        p.paragraph_format.line_spacing=1.15
        p.paragraph_format.space_before=Pt(12)
        p.paragraph_format.space_after=Pt(18)
    elif 'Signature of the Guide' in tx:
        set_paragraph_text(p,'Signature of the Guide\nDr. Thanuja R\nAssociate Professor Grade 1')
        p.paragraph_format.space_before=Pt(38)
        p.paragraph_format.line_spacing=1.15
        p.paragraph_format.space_after=Pt(0)
    elif 'Harsh Ranjan' in tx and 'Jai Goel' in tx and p.style.name=='Body Text':
        set_paragraph_text(p,'Harsh Ranjan\nJai Goel')
        p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before=Pt(42)
        p.paragraph_format.line_spacing=1.25
        p.paragraph_format.space_after=Pt(0)
    elif p.style.name=='Source Code':
        p.paragraph_format.line_spacing=1.1
        p.paragraph_format.space_after=Pt(10)
# Keep data tables compact and prevent a single cell row from splitting across pages.
for table in base.tables:
    for row in table.rows:
        trpr=row._tr.get_or_add_trPr()
        if trpr.find(qn('w:cantSplit')) is None:
            trpr.append(OxmlElement('w:cantSplit'))
        for cell in row.cells:
            for p in cell.paragraphs:
                p.paragraph_format.line_spacing=1.0
                p.paragraph_format.space_after=Pt(0)
# The software-environment table sits at the end of Chapter 3; use 10 pt
# cell text so the final record does not spill alone onto the next page.
if len(base.tables) > 5:
    for row in base.tables[5].rows:
        for cell in row.cells:
            for p in cell.paragraphs:
                for run in p.runs:
                    run.font.size=Pt(10)

# Insert the five figures above their captions in the Word document.
for p in [Paragraph(x,base._body) for x in target_body if x.tag==qn('w:p')]:
    caption_text=p.text.strip()
    matched=None
    for cap,(chap,num,img,width) in figs.items():
        if cap in caption_text:
            matched=(img,width); break
    if matched:
        img,width=matched
        ip=add_before(p,'','Normal'); ip.alignment=WD_ALIGN_PARAGRAPH.CENTER
        ip.paragraph_format.keep_together=True; ip.paragraph_format.keep_with_next=True; ip.paragraph_format.space_after=Pt(2)
        ip.add_run().add_picture(str(DIAGRAMS/img),width=Inches(width))

# Apply direct typography that the original template specifies for cover/abstract.
for p in [Paragraph(x,base._body) for x in target_body if x.tag==qn('w:p')]:
    if p.text.strip()=='Abstract':
        p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        for r in p.runs: r.bold=True; r.font.name='Times New Roman'; r.font.size=Pt(16)
    if p.text.strip().startswith('B.Tech. BCSE497J'):
        p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    if p.style.name=='Source Code':
        for r in p.runs: r.font.name='Courier New'; r.font.size=Pt(9)
# Set doc-level metadata and request Word field refresh on open.
base.core_properties.title='PHANTOM Project Report'
base.core_properties.author='Harsh Ranjan; Jai Goel'
settings=base.settings._element
update=settings.find(qn('w:updateFields'))
if update is None: update=OxmlElement('w:updateFields'); settings.append(update)
update.set(qn('w:val'),'true')
OUT.parent.mkdir(parents=True,exist_ok=True)
base.save(str(OUT))
# Sanity checks for key structures and user details.
check=Document(str(OUT))
alltext='\n'.join(p.text for p in check.paragraphs)
allcells='\n'.join(c.text for tab in check.tables for row in tab.rows for c in row.cells)
assert '23BDS0078' in allcells and '23BDS0191' in allcells
assert len(check.sections)==4, len(check.sections)
assert len(refs)==30
assert all(any(x in p.text for p in check.paragraphs) for x in ('CHAPTER 9','APPENDIX A'))
print(f'created {OUT} paragraphs={len(check.paragraphs)} tables={len(check.tables)} sections={len(check.sections)} references={len(refs)}')
