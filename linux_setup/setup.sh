sudo apt-get update && sudo apt-get upgrade

apt-get install -y netcat

sudo apt-get install zsh
sudo chsh -s `which zsh`   

mkdir -p "$HOME/.zsh"
git clone https://github.com/sindresorhus/pure.git "$HOME/.zsh/pure"
echo "fpath+=("$HOME/.zsh/pure")" >> ~/.zshrc
echo "autoload -U promptinit" >> ~/.zshrc
echo "promptinit" >> ~/.zshrc
echo "prompt pure" >> ~/.zshrc

git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
echo "source ./zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc