from pathlib import Path
import re, subprocess, sys
sys.stdout.reconfigure(encoding='utf-8')
src = Path(r'D:\Downloads\humanized_PHANTOM_Research_Paper_Final.docx')
out = Path(r'D:\project-1\output\Humanized_PHANTOM_Research_Paper_LaTeX\main.tex')
pandoc = r'D:\anaconda3\Library\bin\pandoc.exe'
raw = subprocess.run([pandoc, str(src), '-t', 'latex'], capture_output=True, text=True, encoding='utf-8', errors='replace', check=True).stdout
lines = raw.splitlines()
if len(lines) < 12 or not lines[0].startswith('PHANTOM:') or not lines[11].startswith('Abstract,'):
    raise RuntimeError('Unexpected source document structure; refusing to write LaTeX.')

def clean_line(line):
    return re.sub(r'\\\\$', '', line).strip()

title = [clean_line(lines[0]), clean_line(lines[1])]
authors = [
    (clean_line(lines[2]), clean_line(lines[3]), clean_line(lines[4])),
    (clean_line(lines[5]), clean_line(lines[6]), clean_line(lines[7])),
    (clean_line(lines[8]), clean_line(lines[9]), clean_line(lines[10])),
]
body_lines = lines[11:]
section_titles = {'I. Introduction', 'II. Background and Related Work'}
subsection_titles = {
    'A. Design Distinctions and Research Claims',
    'A. Software Supply Chain Attacks',
    'B. eBPF-Based Runtime Security',
    'C. Software Bill of Materials and Runtime Drift',
    'A. Threat Model', 'A. Experimental Setup',
    'D. RQ3: PCEPS Prediction',
}
header = r'''\documentclass[conference]{IEEEtran}
\usepackage{amsmath,amssymb,booktabs,url,textcomp}
\usepackage{microtype}
\sloppy
\title{%s\\%s}
\author{
\IEEEauthorblockN{%s}
\IEEEauthorblockA{%s\\%s}
\and
\IEEEauthorblockN{%s}
\IEEEauthorblockA{%s\\%s}
\and
\IEEEauthorblockN{%s}
\IEEEauthorblockA{%s\\%s}
}
\begin{document}
\maketitle
''' % (title[0], title[1], *authors[0], *authors[1], *authors[2])

chunks = []
paragraph = []
mode = None

def flush():
    global paragraph
    if paragraph:
        parts = [x.strip() for x in paragraph if x.strip()]
        joined = parts[0] if parts else ''
        for previous, current in zip(parts, parts[1:]):
            separator = r'\\' if previous.endswith('-') else ' '
            joined += separator + current
        if joined:
            chunks.append(joined + '\n')
        paragraph = []

for line in body_lines:
    text = clean_line(line)
    if not text:
        flush()
        if mode is None:
            chunks.append('\\par\n')
        continue
    if text in section_titles:
        flush(); mode = None
        chunks.append(r'\section*{%s}' % text + '\n')
        continue
    if text in subsection_titles:
        flush(); mode = None
        chunks.append(r'\subsection*{%s}' % text + '\n')
        continue
    if text.startswith('Abstract,'):
        flush()
        chunks.append(r'\noindent\textbf{Abstract,} ' + text[len('Abstract,'):].strip() + ' ')
        continue
    if 'Index Terms,' in text:
        before, after = text.split('Index Terms,', 1)
        if before.strip():
            paragraph.append(before.strip())
        flush()
        chunks.append(r'\par\noindent\textbf{Index Terms,} ' + after.strip() + ' ')
        continue
    if text == 'References':
        flush(); mode = 'references'
        chunks.append(r'\section*{References}' + '\n')
        continue
    if text.startswith('TABLE '):
        flush(); mode = 'table'
        chunks.append(r'\par\noindent\textbf{%s}\\' % text + '\n')
        continue
    if text.startswith('Algorithm '):
        flush(); mode = 'algorithm'
        chunks.append(r'\par\noindent\textbf{%s}\\' % text + '\n')
        continue
    if mode in ('table', 'algorithm'):
        chunks.append(text + r'\\' + '\n')
        continue
    if mode == 'references' and re.match(r'^\{\[\}\d+\{\]\}', text):
        flush()
        chunks.append(r'\par\noindent\hangindent=1em\hangafter=1 ' + text + ' ')
        continue
    if text.startswith('•'):
        flush()
        chunks.append(r'\par\noindent\textbullet{} ' + text[1:].strip() + ' ')
        continue
    paragraph.append(text)
flush()
content = header + '\n' + ''.join(chunks) + '\n' + r'\end{document}' + '\n'
# The Pandoc text converter uses \textbar; literal bars are equivalent in these text-mode formulas and round-trip cleanly.
content = content.replace(r'\textbar', '|')
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(content, encoding='utf-8')
print(f'Created {out}; source text length={len(raw)}; LaTeX length={len(content)}.')
