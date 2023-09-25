# Trabalho realizado nas Semanas #2 e #3

# EternalBlue - CVE-2017-0144

## Identificação:

- **Descrição da vulnerabilidade:** CVE-2017-0144, também conhecido como *"Microsoft SMBv1 Remote Code Execution Vulnerability"*, tira proveito do protocolo SMBv1 usado em máquinas Windows, permitindo a execução remota de código.

- **Causa da vulnerabilidade:** Devido a uma validação de input fraca é possivel o envio de pacotes especificos e especialmente construidos que permitem a execução remota de código.

- **Sistemas Operativos relevantes:** Alguns sistemas operativos Windows como por exemplo: Windows Server 2008 SP2 e R2 SP1, Windows 7 SP1, Windows 10 Gold, etc...


## Catalogação:

- **Quem descobriu?** Descoberto pela a agência de segurança dos EUA (*NSA*) e tornado público anos depois pelo grupo *Shadow Brokers*.

- **Quando foi descoberto?** Descoberto por volta do ano 2012. Usado secretamente pela *NSA* durante 5 anos, e tornado público pelo grupo *Shadow Brokers* em 14/04/2017.

- **Nivel de gravidade:** Confirmado como critico pela *Microsoft* devido a possiblidade de execução remota de código. Pontuação 8.1 e vetor associado “CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H”, no sistema *CVSS* na versão 3 (*Common Vulnerability Scoring System*).

- **CWE associado:** Esta vulnerabilidade tem como única fraqueza associada a *CWE-20: Improper Input Validation*. 


## Exploit:

-  **Exploit principal:** *EternalBlue*, desenvolvido pela *NSA*, que garante a execução remota de código.

-  **Descrição do Exploit:** Devido a um erro matemático no protocolo SMBv1 quando este decide quanta memória alocar a um ficheiro. Isto acontece devido a um *integer overflow* que permite a um atacante enviar um pacote especialmente construido que permite a execução remota de código. 

-  **Automação do exploit:** Atacantes podem usar frameworks que automatizam testes de penetração como por exemplo o *Metasploit* onde o *EternalBlue* pode ser encontrado.

## Ataques:

- **Ataques famosos:** Dois dos ataques mais famosos que tiraram proveito desta vulnerabilidade foram o *WannaCry* e o *NotPetya*, ambos ataques de *Ransomware* que usaram o *EternalBlue* como meio de propagação de *malware*.

- **Danos Causados:** Bilhões de euros comprometidos devido aos ataques *Ransomware* e milhares de máquinas comprometidas como por exemplo no banco nacional da Ucrânia, o serviço nacional de saúde Britanico e a *FedEx*.

- **Tentativa de solução:**  A 14/3/2017 antes dos ataques em grande escala ocurrerem a Microsoft lançou uma atualização de segurança que prevenia os ataques, no entanto, a maior parte da população não atualizou as suas máquinas continuando vulneráveis. 


