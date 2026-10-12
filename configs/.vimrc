set modelines=0

" ====================================================================
" GENERAL SETTINGS
" ====================================================================
set nocompatible            " Disable compatibility with old vi
set encoding=utf-8          " Set internal character encoding to UTF-8
set fileencoding=utf-8      " Set default file write encoding
set hidden                  " Allow background buffers to remain open without saving

" ====================================================================
" USER INTERFACE
" ====================================================================
syntax on                   " Enable syntax highlighting
set number                  " Show line numbers
set ruler
set relativenumber          " Show relative line numbers (great for rapid jumping)
set cursorline              " Highlight the current line
set showmode                " Display the current mode (e.g., INSERT, VISUAL)
set showcmd                 " Show partial commands in the status line
set wildmenu                " Enable enhanced visual tab-completion for commands
set lazyredraw              " Don't redraw screen during macros (faster performance)
set ttyfast                 " Smooth out terminal redrawing
set laststatus=2            " Always display the status line
set mouse=a                 " Enable mouse support in all modes (scrolling, clicking)
" set visualbell
set belloff=all
set wrap
set scrolloff=3
set backspace=indent,eol,start
" nnoremap <expr> j (v:count == 0 ? 'gk' : 'k')
" nnoremap <expr> k (v:count == 0 ? 'gj' : 'j')

" ====================================================================
" SEARCH OPTIONS
" ====================================================================
set hlsearch                " Highlight all search matches
set incsearch               " Highlight search matches instantly as you type
set ignorecase              " Ignore case when searching...
set smartcase               " ...unless the search pattern contains uppercase letters
set showmatch
runtime macros/matchit.vim

" ====================================================================
" TABS AND INDENTATION
" ====================================================================
set autoindent              " Copy indent from current line when starting a new one
set smartindent             " Insert indents automatically where appropriate
set tabstop=4               " Number of spaces that a <Tab> counts for
set shiftwidth=4            " Number of spaces to use for each step of auto-indent
set softtabstop=4           " Number of spaces a <Tab> counts for while editing
set expandtab               " Convert all tabs into spaces

" ====================================================================
" FILES, BACKUPS, AND UNDO
" ====================================================================
set nobackup                " Disable backup files (most modern systems don't need them)
set noswapfile              " Disable swap files
set undofile                " Maintain undo history across Vim closures
set undodir=~/.vim/undodir  " Directory where persistent undo files will be stored

" ====================================================================
" KEY REBINDINGS / SHORTCUTS
" ====================================================================
" Set the Leader key to Spacebar (default is backslash)
let mapleader = " "

" Clear search highlights quickly by pressing Space + c
nnoremap <leader>c :noh<CR>

" Fast window navigation using Ctrl + movement keys
nnoremap <C-h> <C-w>h
nnoremap <C-j> <C-w>j
nnoremap <C-k> <C-w>k
nnoremap <C-l> <C-w>l

" Remap jk to Escape when in Insert Mode (saves finger stretching)
inoremap jk <Esc>

" PLUGINS
filetype plugin indent on

" ====================================================================
" AUTOMATIC COMMANDS
" ====================================================================
" Return to the last known cursor position when reopening a file
augroup ResumedPosition
  autocmd!
  autocmd BufReadPost * if line("'\"") > 1 && line("'\"") <= line("$") | exe "normal! g'\"" | endif
augroup END
