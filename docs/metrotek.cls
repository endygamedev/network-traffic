\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{metrotek}


\LoadClass[a4paper,17pt,numbers=endperiod]{extarticle}


\usepackage[main=russian,english]{babel}                                % Русский язык
\usepackage[left=2cm, right=1cm, top=2cm, bottom=2cm, nohead]{geometry} % Отступы
\usepackage[unicode]{hyperref}                                          % Ссылки
\usepackage{indentfirst}                                                % Отступ у первого абзаца
\usepackage{import}                                                     % Разные страницы
\usepackage{graphicx}                                                   % Картинки
\usepackage{totcount}                                                   % Счётчик страниц
\usepackage{tikz}                                                       % Работа с картинками
\usepackage{setspace}                                                   % Интервалы
\usepackage{enumitem}                                                   % Списки
\usepackage{listings}                                                   % Листинг кода
\usepackage{secdot}                                                     % Точка после заголовка
\usepackage{color}                                                      % Цвета


% Цвета ссылок
\hypersetup{
    colorlinks=true,
    linkcolor=black,
    urlcolor=blue
}

% Отступы для списков
\setlist{nolistsep}

% Задание отступов
\renewcommand{\baselinestretch}{1.5}
\setlength{\baselineskip}{14pt}
\linespread{1.1}
\setlength{\parskip}{0em}
\setlength\parindent{0cm}
\setlength{\belowcaptionskip}{-14pt}
\emergencystretch=1em
\newcommand{\linespace}{\vspace{0.5cm}}

% Внутренний enumerate
\renewcommand{\labelenumii}{\theenumii}
\renewcommand{\theenumii}{\arabic{enumii}.}

% Для листингов кода
\definecolor{dkgreen}{rgb}{0,0.6,0}
\definecolor{gray}{rgb}{0.5,0.5,0.5}
\definecolor{mauve}{rgb}{0.58,0,0.82}

\lstset{
    frame=none,
    aboveskip=3mm,
    belowskip=3mm,
    showstringspaces=false,
    columns=flexible,
    basicstyle={\small\ttfamily},
    numbers=none,
    numberstyle=\small\color{gray},
    keywordstyle=\color{blue},
    commentstyle=\color{dkgreen},
    stringstyle=\color{mauve},
    breaklines=true,
    breakatwhitespace=true,
    tabsize=4
}

% Точка после числа в оглавлении
\let \savenumberline \numberline
\def \numberline#1{\savenumberline{#1.}}
