# use Pod::Perldoc::ToMarkdown to conver the pod to a markdown file

perldoc -o Markdown capstan.pl > README.md
perldoc capstan.pl > README.pod
