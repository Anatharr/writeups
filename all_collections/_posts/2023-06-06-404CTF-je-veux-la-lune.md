---
layout: post
title: 404CTF 2023 | Je veux la lune !
image: /assets/images/404ctf/je-veux-la-lune/cover.png
date: 2023-06-06 23:40:00
categories: [404ctf, pwn]
---

This challenge was part of the [404CTF 2023](https://www.404ctf.fr/), organized by the General Directorate for External Security (DGSE) and Télécom SudParis.

# Challenge Description

![Challenge Description]({{site.baseurl}}/assets/images/404ctf/je-veux-la-lune/description.png)

>> Caligula est assis seul devant une table du café. Il y a devant lui 5 tasses vides empilées, et une 6e qu'il sirote lentement, ainsi qu'un ordinateur qu'il regarde fixement. Des cernes profonds creusent son visage. Il lève des yeux étonnamment vifs vers vous alors que vous vous approchez de lui.
>>
>> Il tend sa main vers son écran d'un air désespéré et s'exclame « Je ne peux plus vivre comme ça, ce monde n'est pas supportable. J'ai besoin de quelque chose de différent. Quelque chose d'impossible, peut-être le bonheur, ou peut-être la lune... Et je sens que ma quête s'approche de sa fin. »
>>
>> Vous regardez son écran, et voyez qu'il tente d'accéder sans succès à un fichier.
>>
>> « Vous pensez que je suis fou, mais je n'ai jamais pensé aussi clairement ! » Un calcul rapide vous informe qu'il a probablement consommé plus d'un litre de café, et il n'est que 13h. Vous acquiescez lentement. Il reprend « Regardez, Hélicon m'a enfin rapporté la lune, mais il ne m'a pas donné l'accès... le fourbe. Je brûlerai un quart de sa fortune plus tard pour le punir. Aidez-moi ! »
>>
>> Entre peur et pitié, vous décidez de l'aider à obtenir le contenu du fichier secret.
>>
>> chlmine#0024

# Analysis

The given `donne_moi_la_lune.sh` file contains a simple script :

```sh
#!/bin/bash

Caligula=Caius

listePersonnes="Cherea Caesonia Scipion Senectus Lepidus Caligula Caius
 Drusilla"

echo "Bonjour Caligula, ceci est un message de Hélicon. Je sais que
 les actionnaires de ton entreprise veulent se débarrasser de toi, je
 me suis donc dépêché de t'obtenir la lune, elle est juste là dans le
 fichier lune.txt !

En attendant j'ai aussi obtenu des informations sur Cherea, Caesonia,
 Scipion, Senectus, et Lepidus, de qui veux-tu que je te parle ?"
read personne
eval "grep -wie ^$personne informations.txt"

while true; do
    echo "
De qui d'autre tu veux que je te parle ?"
    read personne

    if [ -n $personne ] && [ $personne = "stop" ] ; then
    exit
    fi

    bob=$(grep -wie ^$personne informations.txt)
    
    if [ -z "$bob" ]; then
        echo "Je n'ai pas compris de qui tu parlais. Dis-moi stop si
         tu veux que je m'arrête, et envoie l'un des noms que j'ai
         cités si tu veux des informations."
    else
        echo $bob
    fi  

done
```

According to the prompt, it looks like the goal is to get the content of the file `lune.txt`. To do so, we can see in the script that our input is not escaped and is directly passed to `grep`, allowing code injection. We are then able to recover the flag with a simple payload like `404CTF lune.txt` (note the space, which makes bash interpret the next string as another argument), which will result in the following `grep` command, effectively showing all lines beginning with `404CTF` on both files :

```sh
grep -wie ^404CTF lune.txt informations.txt
```

# Running on the remote server

Let's try this payload !

![Exploit]({{site.baseurl}}/assets/images/404ctf/je-veux-la-lune/expl.png)

> ✅ Flag : `404CTF{70n_C0EuR_v4_7e_1Ach3R_C41uS}`