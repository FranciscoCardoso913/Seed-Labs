# Environment Variable and Set-UID Program Lab

### Task 1: Manipulating Environment Variables

Nesta task, limitamo-nos a seguir os passos descritos no guião.
Primeiro corremos os comandos `printenv` e `env`, verificando que estes imprimiam todas as nossas variáveis de ambiente, como esperado.
De seguida corremos os comandos `printenv PWD` e `env | grep PWD` verificando que ambos imprimiam o valor da variável de ambiente PWD.
Após isso, corremos o comando `unset PWD`, verificando que essa variável de ambiente é apagada das nossas variáveis de ambiente (output vazio ao correr `printenv PWD`). Por último, corremos o comando `export PWD=/home/seed`, repondo o valor inicial da variável de ambiente PWD. 

### Task 2: Passing Environment Variables from Parent Process to Child Process

Verificámos ao ler o manual que, como dito no guião, certos aspetos não são herdados do processo pai pelo processo filho. Por exemplo, o _id_ do processo filho é único e diferente do _id_ do pai.
Ao correr o programa e ao guardar os resultados das variáveis de ambiente do processo filho e do processo pai em dois ficheiros diferentes, conseguimos com o auxilio da função `diff` verificar que as variáveis de ambiente dos dois processos são iguais. Assim, concluímos que ao usar a função `fork()`, o processo filho herda as variáveis de ambiente do processo pai.

### Task 3: Environment Variables and execve()

Começámos por correr o programa com a função de `execve` a receber `NULL` como terceiro argumento, com isto verificámos que o novo processo não continha variáveis de ambiente.
De seguida voltamos a correr o programa mas desta vez passamos a lista de variáveis de ambiente do processo original no terceiro argumento da função `execve`, verificando que o novo processo fica com essas variáveis de ambiente.
Concluímos assim que numa chamada da função `execve`, o novo processo não herda as variáveis de ambiente do processo original. Na verdade, o novo processo recebe as variáveis de ambiente que são passadas no terceiro argumento da função `execve`.

### Task 4: Environment Variables and system()

Compilámos e corremos o código fornecido e verificamos que as variáveis de ambiente que são imprimidas são as mesmas que o processo atual.

### Task 5: Environment Variable and Set-UIDPrograms

Como descrito no guião, começamos por alterar os valores das seguintes variáveis de ambiente:

 <ul>
 <li>PATH=$PATH:/usr</li>
 <li>LD_LIBRARY_PATH=/home</li>
 <li>TEST=test</li>
 <li>LD_MY_LIB=/home</li>
 </ul>

Sendo as variáveis "TEST" e "LD_MY_LIB" criadas por nós. 
Ao correr o programa com owner **root** e permissões **4755**, verificámos que o processo filho herda todas as variáveis de ambiente menos a variável LD_LIBRARY_PATH. O facto de o processo filho não ter conseguido herdar a variável de ambiente LD_LIBRARY_PATH surpreendeu-nos.

### Task 6: The PATH Environment Variable and Set-UID Programs

Primeiramente fizemos tudo de acordo com o guião (definir o PATH e compilar o código fornecido, mudando as permissões e o dono do executável). Depois criámos um ficheiro `myls.c` com o seguinte código em C, na pasta /home/seed:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
	printf("Hello World!\n");
	system("cat /etc/shadow");
	return 0;
}
```

Compilámos esse programa da seguinte forma `gcc myls.c -o ls`. Por fim, corremos o executável do código que nos é fornecido no guião. Foi imprimida a string `"Hello World!"`, como esperado, e a string `cat: /etc/shadow: Permission denied`, o que sugere que apesar de conseguirmos corrermos o nosso script `ls`, não o corremos com permissões **root**, devido à contramedida da *shell* *dash* descrita no guião. 

Corremos então `sudo ln -sf /bin/zsh /bin/sh` como dito no guião e repetimos o processo, verificando que desta vez os conteúdos do ficheiro `/etc/shadow` foram imprimidos, concluindo que desta vez corremos o nosso executável `ls` com permissões **root**.