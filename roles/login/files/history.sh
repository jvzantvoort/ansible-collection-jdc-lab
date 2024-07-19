[[ -d $HOME/.history ]] && { export HISTFILE=$HOME/.history/$HOSTNAME ; } || { export HISTFILE=$HOME/.history ; }
export HISTSIZE=10000
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=ignoredups
