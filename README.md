# Secret Sealer

Een web-app om secrets te versleutelen voor [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets).
Het sealen gebeurt **volledig in de browser**: je hebt alleen de public cert van een cluster nodig. Je hoeft
niet in te loggen, er is geen 2FA, geen `oc`/`kubectl` en geen `kubeseal`. Je geheim verlaat je computer niet.

De uitvoer is byte-compatibel met `kubeseal` (RSA-OAEP/SHA-256 + AES-256-GCM, zelfde scope-labels).
Dat is getest tegen de officiële Go-library (`github.com/bitnami/sealed-secrets` v0.41.2): zowel losse
waardes (`HybridDecrypt`) als complete manifesten (`SealedSecret.Unseal`, het pad van de controller).

## Wat kan het?

- **Losse waarde**: één waarde (ook meerdere regels) sealen, net als `kubeseal --raw`. Plak het resultaat
  in `spec.encryptedData` of in je Helm-values.
- **Volledig SealedSecret**: meerdere keys in één keer, met een kant-en-klaar manifest om te kopiëren of
  te downloaden.
- **Scopes**: namespace-wide (standaard, instelbaar), strict (namespace + naam) en cluster-wide.
- **Clusters uit config**, plus de optie om ad hoc een eigen certificaat te plakken.
- Controle op namespace-, naam- en key-formaat. Waarschuwt bij een afsluitende spatie of lege regel, een
  klassieke bron van "werkt niet in productie".
- Een resultaat verdwijnt zodra je de invoer wijzigt, zodat je nooit een verouderde waarde kopieert.
- `Ctrl`/`⌘` + `Enter` om te versleutelen. Cluster, namespace en scope worden lokaal onthouden; waardes niet.

## Configuratie

De app leest bij het opstarten `config/clusters.json`:

```json
{
  "defaultScope": "namespace-wide",
  "clusters": [
    {
      "id": "ont",
      "name": "Ontwikkel",
      "certificateUrl": "config/certs/ont.pem",
      "namespaces": ["team-a-ont", "team-b-ont"]
    }
  ]
}
```

| Veld | Betekenis |
| --- | --- |
| `defaultScope` | `namespace-wide`, `strict` of `cluster-wide`. Wat er standaard geselecteerd is. |
| `clusters[].certificateUrl` | Public sealing-cert (PEM), op dezelfde origin als de app. |
| `clusters[].namespaces` | Optioneel: suggesties in het namespace-veld. |

Een cert ophaal je met:

```bash
kubeseal --controller-namespace <ns> --controller-name <naam> --fetch-cert > ont.pem
```

Public certs zijn niet geheim en mogen gewoon in Git of een ConfigMap staan. Als de controller zijn sleutel
roteert (standaard elke 30 dagen), blijven oude certs werken; ververs ze af en toe.

> In `public/config` staat een **demo**-cluster met een testcertificaat waarvan de private key niet
> bewaard is. Daarmee gesealde waardes kan niemand ontsleutelen. Vervang de config voor echt gebruik.
> De devserver (`npm start`) blokkeert `*.pem`/`*.crt`, daarom heet het democert `demo.cert`. Onder nginx
> werkt `.pem` gewoon.

## Ontwikkelen

Vereist Node 24 (Angular 21).

```bash
npm install
```

```bash
npm start          # http://localhost:4200
```

```bash
npm test           # unit tests (Vitest)
```

De crypto staat in `src/app/sealing/` en heeft geen dependencies; WebCrypto doet het werk.

## Deployen op OpenShift

De `Dockerfile` bouwt de app en serveert die met `nginx-unprivileged` op poort 8080 (draait onder een
willekeurige UID). `nginx.conf` zet een strikte Content-Security-Policy (`connect-src 'self'`): de pagina
kan nergens anders heen praten.

Mount je echte config over de demo heen met een ConfigMap:

```yaml
volumes:
  - name: config
    configMap:
      name: secret-sealer-config   # bevat clusters.json en de certs
      items:
        - { key: clusters.json, path: clusters.json }
        - { key: ont.pem, path: certs/ont.pem }
volumeMounts:
  - name: config
    mountPath: /usr/share/nginx/html/config
```
