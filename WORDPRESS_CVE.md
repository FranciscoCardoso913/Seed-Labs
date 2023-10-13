# CTF Wordpress CVE 

## Reconhecimento:
 
Chegando à homepage do website da ***Secure WP Hosting*** reparámos na secção de últimos comentários no website. Isso destacava um comentário de um admin e de um user “Orval Sanford”. Anotámos esses dois users após considerar que poderiam ser uteis mais tarde. Carregámos no link de um dos comentários, que nos levou à página de um dos artigos da loja (o que tinha o comentário). Nessa página existe uma *tab* que diz “Informações adicionais”, onde encontrámos a versão do *Wordpress* e a versão dos dois plugins de *Wordpress* usados no website: *Woocommerce v5.8.1* e *Booster for Woocommerce plugin 5.4.3.*. Para além disso também reparamos que o website continha uma feature de login e uma feature de repor a palavra-passe usando verificação de email. Sendo o objetivo do CTF aceder a conta de admin anotámos estes dois serviços como possíveis vulnerabilidades.

## Pesquisa por vulnerabilidades

Depois desta fase de reconhecimento procurámos no site https://cve.mitre.org/ por CVEs conhecidos das tecnologias que anotámos nas suas respetivas versões. Procurámos primeiro por CVEs de [Wordpress v5.8.1](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Wordpress+5.8.1), dando-nos 3 resultados. No entanto, nenhum deles se encaixava no que queríamos: um falava de uma vulnerabilidade no plugin “The Essential Addons for Elementor", outro plugin chamado “EWWW Image Optimizer”, e o outro falava de que essa vulnerabilidade estava patched nesta versão de *Wordpress*.
Decidimos depois procurar por CVEs de [Booster for Woocommerce plugin 5.4.3.](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Booster+for+Woocommerce+5.4.3), dando-nos um só o seguinte resultado [CVE-2021-34646](https://nvd.nist.gov/vuln/detail/CVE-2021-34646), que descreve que este plugin está vulnerável a um desvio de autenticação através do uso da funcionalidade de recuperação da palavra passe, que recorre a um serviço de verificação de email do *Wordpress*.

## Escolha da vulnerabilidade
Sendo o objetivo do CTF tomar posse de uma conta admin e tendo já verificado que o website usava o serviço de verificação de email do *Wordpress* decidimos escolher o [CVE-2021-34646](https://nvd.nist.gov/vuln/detail/CVE-2021-34646) como vulnerabilidade para explorar. O CVE descreve que para a vulnerabilidade existir, o módulo de verificação de email teria de estar ativo (verificámos já que esse módulo existe) e a definição "Login User After Successful Verification" teria de estar ativa, estando ativa por default.

## Encontrar um exploit
Após perceber como o CVE funcionava encontrar um exploit foi fácil, como uma simples pesquisa na [Exploit Database](https://www.exploit-db.com/) encontramos um [exploit](https://www.exploit-db.com/exploits/50299) que utilizava o [CVE-2021-34646](https://nvd.nist.gov/vuln/detail/CVE-2021-34646) para ganhar acesso a uma conta através de desvio de autenticação. Após perceber como funcionava decidimos escolher este exploit para o ataque.

## Explorar a vulnerabilidade

Com o exploit escolhido o ataque foi uma tarefa simples. Na [página do Exploit Database referente ao exploit escolhido](https://www.exploit-db.com/exploits/50299) encontrava-se um script de *python* com  o código necessário para executar o ataque. Assim, a única coisa necessária foi correr o programa python com "http://ctf-fsi.fe.up.pt:5001/ {admin_user_id}" como argumento (confirmámos o id do admin ao aceder a https://target.com/wp-json/wp/v2/users/, como descrito num comentário do exploit), obtendo assim 3 links sendo um deles o link para aceder à conta admin. Com o acesso à conta admin restou-nos encontrar o post privado que continha a flag: **flag{please don't bother me}**
