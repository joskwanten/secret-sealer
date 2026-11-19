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
- **Scopes**: cluster-wide (standaard, instelbaar), namespace-wide en strict (namespace + naam).
- **Clusters uit config**, plus de optie om ad hoc een eigen certificaat te plakken.
- Controle op namespace-, naam- en key-formaat. Waarschuwt bij een afsluitende spatie of lege regel, een
  klassieke bron van "werkt niet in productie".
- Een resultaat verdwijnt zodra je de invoer wijzigt, zodat je nooit een verouderde waarde kopieert.
- `Ctrl`/`⌘` + `Enter` om te versleutelen. Cluster, namespace en scope worden lokaal onthouden; waardes niet.

## Configuratie

De app leest bij het opstarten `config/clusters.json`:

```json
{
  "defaultScope": "cluster-wide",
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
| `clusters[].namespaces` | Optioneel: vaste lijst namespaces om uit te kiezen. |
| `clusters[].namespacesUrl` | Optioneel: URL die een JSON-lijst namespaces teruggeeft; gaat voor `namespaces`. |

Een cert ophaal je met:

```bash
kubeseal --controller-namespace <ns> --controller-name <naam> --fetch-cert > ont.pem
```

Public certs zijn niet geheim en mogen gewoon in Git of een ConfigMap staan. Als de controller zijn sleutel
roteert (standaard elke 30 dagen), blijven oude certs werken; ververs ze af en toe.

> In `web/config` staat een **demo**-cluster met een testcertificaat waarvan de private key niet
> bewaard is. Daarmee gesealde waardes kan niemand ontsleutelen. Vervang de config voor echt gebruik.

## Hoe zit het in elkaar?

Er is geen framework en geen build-stap. Wat in `web/` staat, is precies wat de browser krijgt.

| Map / bestand | Wat |
| --- | --- |
| `web/` | De pagina: `index.html`, `styles.css` en gewone ES-modules (`app.js`, `combobox.js`, `config.js`). |
| `web/sealing/` | De crypto. Geen dependencies; WebCrypto doet het werk. |
| `main.go` | Klein Go-programma voor lokaal gebruik (zie hieronder). Bakt `web/` in en gebruikt alleen de standaardbibliotheek. |
| `test/` | Unit tests voor de crypto (`node --test`). |
| `nginx.conf`, `Dockerfile` | De image voor OpenShift: alleen nginx met de bestanden uit `web/`. |

De JS heeft JSDoc-types. VS Code controleert die via `jsconfig.json`, dus je houdt type-checking zonder
TypeScript-build.

## Lokaal gebruiken (één programma)

`main.go` serveert de app op `http://localhost:8080` en opent je browser. Daarbij haalt het het cert live op
via `kubeseal --fetch-cert`, met jouw eigen `oc login`. Je hebt dan geen cert-bestanden nodig. Kies in de app
**Huidige oc-login**. De app laat zien van welk API-adres het cert komt. Log je in op een ander cluster, klik dan
op *vernieuwen*.

```bash
go run .
```

Of bouw één bestand dat je kunt delen of in je PATH zet:

```bash
GOOS=windows GOARCH=amd64 go build -o secret-sealer.exe .
GOOS=darwin  GOARCH=arm64 go build -o secret-sealer-mac .
go build -o secret-sealer .
```

Het namespace-veld is een combobox: kies uit de lijst of typ om te filteren. De lijst komt live uit
`oc get projects`, dus precies de projecten waar jij bij kunt (daar zijn geen clusterrechten voor nodig).
Een namespace die er niet bij staat typ je gewoon in. Lukt het ophalen niet, dan blijft het een gewoon
tekstveld.

Voorwaarden: `kubeseal` staat in je PATH (`scoop install kubeseal`) en je bent ingelogd met `oc login`.
`oc` is optioneel en wordt gebruikt voor de namespaces en om het API-adres te tonen (met `kubectl` als
terugval).

| Optie | Betekenis |
| --- | --- |
| `-addr` | Adres, standaard `127.0.0.1:8080`. |
| `-config <pad>` | Eigen `clusters.json` in plaats van de ingebouwde (`local-config/clusters.json`). |
| `-open=false` | Browser niet automatisch openen. |
| `-dev` | Serveer `web/` van schijf, zodat een wijziging na een refresh zichtbaar is. |

- De controller staat standaard op `cd-sealed-secrets/sealed-secrets`. Overschrijf dat met de
  omgevingsvariabelen `SEALED_SECRETS_NAMESPACE` en `SEALED_SECRETS_NAME`.
- Een vaste kubeconfig-context voeg je toe in de clusterlijst met `"certificateUrl": "live-certs/<context>"`
  (URL-encoded; contextnamen vind je met `oc config get-contexts`).
- Het programma antwoordt alleen op verzoeken voor `localhost`/`127.0.0.1`. Een andere website kan de
  live-endpoints (die met jouw login draaien) dus niet via een DNS-truc aanroepen.
- Het geheim zelf komt nooit bij dit programma: ook hier versleutelt de browser.

### Of: plak je `oc login`-commando

Heb je `oc` of `kubeseal` niet (of wil je naar een ander cluster zonder opnieuw in te loggen), kies dan
**Geplakte oc login**. Plak het commando uit de OpenShift-console (je naam rechtsboven → *Copy login command*),
bijvoorbeeld:

```
oc login --token=sha256~… --server=https://api.ont.example:6443
```

Het Go-programma praat dan zelf met de Kubernetes-API: het cert komt via de service-proxy van de controller (net
als `kubeseal --fetch-cert`) en de namespaces uit de projects-API. `oc` en `kubeseal` zijn dan niet nodig.

- De token staat alleen in het geheugen van het Go-programma: niet op schijf en niet in de browser. Herstart je
  het programma of verloopt de token, dan plak je opnieuw. *verbreken* vergeet hem meteen.
- Alleen de Secret Sealer-pagina zelf mag een login instellen; een andere website kan dat niet.
- Het certificaat van de API-server moet vertrouwd worden door je OS. Is dat niet zo, voeg dan
  `--insecure-skip-tls-verify` aan het commando toe, net als bij `oc`.
- Dit werkt alleen lokaal, niet in de nginx-versie op OpenShift.

## Ontwikkelen

Vereist Go 1.24+ en, voor de tests van de crypto, Node 22+. Er is geen `npm install` nodig.

```bash
go run . -dev      # http://localhost:8080, wijzigingen in web/ na een refresh zichtbaar
```

```bash
node --test "test/*.test.js"   # crypto en manifest (of: npm test)
go test ./...                  # de Go-server
```

## Deployen op OpenShift

De `Dockerfile` heeft geen build-stap: hij zet `web/` in `nginx-unprivileged` op poort 8080 (draait onder een
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
