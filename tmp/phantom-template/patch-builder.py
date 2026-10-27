from pathlib import Path
p=Path(r'D:\project-1\tmp\phantom-template\build_word_report.py')
t=p.read_text(encoding='utf-8')
t=t.replace("""    for r in list(p._p.findall(qn('w:r'))):
        p._p.remove(r)
    for h in list(p._p.findall(qn('w:hyperlink'))):
        p._p.remove(h)
""", """    for child in list(p._p):
        if child.tag != qn('w:pPr'):
            p._p.remove(child)
""")
t=t.replace("f'{n}. {label.title() if n!=1 else \"INTRODUCTION\"}'", "f'{n}. {label}'")
t=t.replace("'The window score is the weighted conditional divergence is D_KL = sum_h (n_h/N) sum_x '", "'The window score is the weighted conditional divergence shown below.'")
t=t.replace("""    if p.text.strip() in front_page_heads:
        p.paragraph_format.page_break_before=True
        p.paragraph_format.keep_with_next=True
""", """    if p.text.strip() in front_page_heads:
        p.paragraph_format.page_break_before=True
        p.paragraph_format.keep_with_next=True
        p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        set_paragraph_text(p,p.text.strip().upper())
""")
t=t.replace("""        if caption_text.startswith(f'Figure {chap}.{num}:') or caption_text.startswith(f'Figure {chap}.{num}.'):
            matched=(img,width); break
""", """        if cap in caption_text:
            matched=(img,width); break
""")
t=t.replace("""        ip.paragraph_format.keep_together=True; ip.paragraph_format.space_after=Pt(2)
""", """        ip.paragraph_format.keep_together=True; ip.paragraph_format.keep_with_next=True; ip.paragraph_format.space_after=Pt(2)
""")
t=t.replace("""alltext='\\n'.join(p.text for p in check.paragraphs)
assert '23BDS0078' in alltext and '23BDS0191' in alltext
""", """alltext='\\n'.join(p.text for p in check.paragraphs)
allcells='\\n'.join(c.text for tab in check.tables for row in tab.rows for c in row.cells)
assert '23BDS0078' in allcells and '23BDS0191' in allcells
""")
# Avoid relabeling already numbered Appendix headings in the chapter numbering pass.
t=t.replace("""    m=chapter_start_re.match(p.text.strip())
    if m:
        current_chapter=int(m.group(1)); sec=0; sub=0; continue
    if current_chapter and p.style.name in ('Heading 2','Heading 3'):
""", """    m=chapter_start_re.match(p.text.strip())
    if m:
        current_chapter=int(m.group(1)); sec=0; sub=0; continue
    if p.text.strip()=='APPENDIX A':
        current_chapter=None; sec=0; sub=0; continue
    if p.text.strip().startswith(('A.1 ', 'A.2 ')):
        continue
    if current_chapter and p.style.name in ('Heading 2','Heading 3'):
""")
# Remove repeated longtable header from the modules table.
t=t.replace("""# Repair the symbols whose math syntax was dropped by the converter.
""", """# Remove the duplicate repeated header row from the long modules table.
if len(source.tables) > 7 and len(source.tables[7].rows) > 1:
    first=[c.text.strip() for c in source.tables[7].rows[0].cells]
    second=[c.text.strip() for c in source.tables[7].rows[1].cells]
    if first==second and first and first[0]=='Module':
        source.tables[7]._tbl.remove(source.tables[7].rows[1]._tr)

# Repair the symbols whose math syntax was dropped by the converter.
""")
p.write_text(t,encoding='utf-8')
