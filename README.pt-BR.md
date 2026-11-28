<p align="center">
  <img src="assets/banner.svg" alt="Strig: quem pode fazer o quê, e por quê. RBAC, ABAC e ReBAC num motor de decisão para Rust." width="100%">
</p>

# Strig

[![CI](https://github.com/The-Hades-Organization/Strig/actions/workflows/ci.yml/badge.svg)](https://github.com/The-Hades-Organization/Strig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)
[![crates.io](https://img.shields.io/crates/v/strig.svg)](https://crates.io/crates/strig)
[![docs.rs](https://img.shields.io/docsrs/strig)](https://docs.rs/strig)
[![npm](https://img.shields.io/npm/v/@the-hades-organization/strig.svg)](https://www.npmjs.com/package/@the-hades-organization/strig)

[English](README.md) · **Português (Brasil)**

Strig é uma biblioteca de autorização em Rust. Você declara um catálogo de permissões, entrega seus grants ao motor e pergunta se um sujeito pode fazer algo num recurso. RBAC, ABAC e ReBAC são avaliados sobre os mesmos grants. As mudanças nos grants passam por regras de governança, ficam na auditoria e podem chegar em tempo real às outras instâncias e ao navegador.

O núcleo não faz IO, não precisa de runtime assíncrono e compila para WebAssembly. Tempo real, transportes e os bindings JavaScript ficam em crates separados e opcionais.

[Documentação](https://strig.vercel.app/docs) · [Playground](https://strig-playground.vercel.app) · [API no docs.rs](https://docs.rs/strig) · [Changelog](CHANGELOG.md)

> [!NOTE]
> A Strig ainda não chegou à 1.0: a API pode mudar entre versões menores. Até a 0.5.0 o projeto saiu com o nome Themis. A [política de versão e depreciação](docs/versioning.md) diz o que é API pública e o que a quebra, o [migration.md](docs/migration.md) mostra o que mudar ao atualizar e os [benchmarks](docs/benchmarks.md) trazem os números (os três guias estão em inglês).

## Instalação

```sh
cargo add strig                             # Rust
cargo add strig --features dsl              # Rust, com a linguagem de políticas
npm install @the-hades-organization/strig   # Node, Bun e navegador
pip install strig-auth                     # Python (import strig)
```

Features do crate `strig`:

| Feature | Padrão | Acrescenta |
|---|---|---|
| `audit` | sim | Trilha de auditoria das mudanças de grant e das decisões, com cadeia de hash |
| `exclusive` | não | Um detentor por recurso, com prioridade e preempção |
| `conformance` | não | Liga `exclusive` e traz `strig::exclusive_conformance`, a bateria que um adaptador de `ExclusiveStore` roda nos testes (fora da API estável) |
| `dsl` | não | A linguagem de políticas: parse, validação, conversão, formatação. Sem IO, funciona em wasm |
| `dsl-fs` | não | `dsl` mais leitura e escrita de arquivos e diretórios `.strig` |

## Primeiros passos

```rust
use strig::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::builder()
        .target_kinds(["project", "doc_type", "document"])
        .broad_target("org")
        .permission(PermissionDef::new("document.export").targets(["project", "document"]))
        .permission(
            PermissionDef::new("document.invoice.export")
                .targets(["doc_type", "document"])
                .implied_by(["document.export"]),
        )
        .build()?;

    let engine = Engine::builder(catalog).build()?;

    let grants = vec![
        Grant::allow("g1", SubjectMatcher::role("member"), "document.export", TargetSelector::kind("org"))
            .scoped(Anchor::new("org", "acme")),
        Grant::deny("g2", SubjectMatcher::Any, "document.invoice.export", TargetSelector::exact("doc_type", "invoice")),
    ];

    let dave = Subject::user("dave").with_role_in("member", Anchor::new("org", "acme"));
    let invoice = Resource::new("document", "d1")
        .within("doc_type", "invoice")
        .within("project", "p1")
        .within("org", "acme");

    let ctx = Context::new(&grants);
    let export_invoice = engine.decide(&ctx, &Request::new(&dave, "document.invoice.export", &invoice));
    let export = engine.decide(&ctx, &Request::new(&dave, "document.export", &invoice));
    println!("{:?} {:?}", export_invoice.effect, export_invoice.reason);
    println!("{:?} {:?}", export.effect, export.reason);
    Ok(())
}
```

```text
Deny Grant { grant_id: "g2", permission: "document.invoice.export", rank: 1, strategy: "most_specific" }
Allow Grant { grant_id: "g1", permission: "document.export", rank: 3, strategy: "most_specific" }
```

O Dave exporta documentos em qualquer lugar de `acme` (`g1`), mas não faturas: `g2` está em `doc_type:invoice`, a um degrau do documento (`rank: 1`), e `g1` está em `org:acme`, a três degraus (`rank: 3`). O rank conta os degraus a partir do próprio recurso (rank 0), e a estratégia padrão deixa o menor rank decidir.

O mesmo motor roda no Node, no Bun e no navegador; veja [JavaScript](#javascript-node-bun-e-navegador).

O mesmo motor pode ser configurado em JSON, TOML ou YAML via `EngineSpec`, ou a partir de um arquivo `.strig` na [linguagem de políticas](#linguagem-de-políticas). `EngineSpec::builder()` devolve o `EngineBuilder`, para você acrescentar em código o que não serializa, como funções de condição.

Mais para rodar:

```sh
cargo run -p strig --example documents        # RBAC, ABAC e ReBAC num mesmo domínio
cargo run -p strig-axum --example server      # servidor de tempo real sobre SSE e WebSocket
```

## Crates

Todos os crates, menos `strig-inspect`, `strig-node`, `strig-python`, `strig-wasi` e `strig-lsp`, estão no crates.io na mesma versão.

| Crate | Use para | Dependências principais |
|---|---|---|
| `strig` | Catálogo, motor de decisão, governança, auditoria, spec em JSON, linguagem de políticas | `serde`, `thiserror`; `sha2` com `audit` |
| `strig-sync` | Hub de mudanças, trait `Transport`, sessões SSE/WebSocket independentes de framework web, cache de capacidades | `tokio` |
| `strig-redis` | `Transport` sobre Redis pub/sub | `redis` |
| `strig-postgres` | `Transport` sobre Postgres `LISTEN/NOTIFY`, enviado dentro da sua transação; grants, tuplas, papéis e pedidos pendentes guardados no Postgres | `tokio-postgres` |
| `strig-axum` | Rotas SSE e WebSocket do axum sobre as sessões do `strig-sync` | `axum` |
| `strig-server` | Servidor HTTP de decisão, e um cliente Rust que nega quando não recebe resposta | `axum`, `hyper-util` (cliente) |
| `strig-macros` | `policy!` e `include_policy!`: a política é validada em tempo de compilação | `strig` |
| `strig-node` | O pacote npm: módulo nativo (N-API) para Node e Bun, WebAssembly para navegador | `napi` ou `wasm-bindgen` |
| `strig-python` | O pacote PyPI `strig-auth` (`import strig`): extensão nativa (PyO3, abi3) sobre o mesmo núcleo do `strig-node` | `pyo3` |
| `strig-wasi` | O módulo WebAssembly com ABI C que os bindings de Go e da JVM executam: JSON na entrada, JSON na saída, sem `wasm-bindgen` | `strig-node` |
| `strig-cli` | O comando `strig`: `strig test` roda os testes de uma política, para pessoas e para o CI (JUnit) | `strig` |
| `strig-lsp` | Language server para arquivos `.strig` por stdio: diagnósticos, formatação, completar, hover, ir para definição, converter (compilado do fonte; a extensão do VS Code está em `editors/vscode`) | `strig`, `lsp-server` |
| `strig-inspect` | Visualizador: rastro das decisões, simulação de grants, matriz de acesso, trilha de auditoria. Janela desktop e comandos de terminal | `gpui-pre`, `gpui-component` |

```toml
[dependencies]
strig = "0.6"
strig-sync = "0.6"
```

## Conceitos

| Conceito | Tipo | O que guarda |
|---|---|---|
| Catálogo | `Catalog`, `PermissionDef` | Chaves de permissão pontilhadas (`document.invoice.export`), os alvos que cada uma aceita, `implied_by`, metadados livres (`meta`). Exporta e importa JSON. |
| Recurso | `Resource`, `Anchor` | Caminho de degraus (âncoras) do mais específico ao mais amplo (`document:7 → doc_type:invoice → project:42 → org:9`), com um `global` implícito no fim, mais atributos. |
| Sujeito | `Subject` | Id, papéis (com escopo opcional), principais (`authenticated`, `anonymous` ou próprios), atributos. |
| Grant | `Grant` | Quem (`User`, `Role`, `Principal`, `Relation`, `Any`), qual permissão, em qual alvo (um tipo ou um degrau exato), permite ou nega, com escopo (uma âncora por onde o caminho do recurso tem de passar) e condição opcionais. |
| Motor | `Engine` | Decide. Devolve uma `Decision` com o efeito, o motivo, os grants casados e os avisos. |
| Governança | `Governance`, `Invariant` | Aplica uma mudança de grant só se todos os invariantes passarem, e audita o resultado. |

O catálogo é validado na construção. Ele recusa chave mal formada, duplicata, alvo não registrado, pai inexistente, ciclo e o que a sua `CatalogRule` rejeitar.

## Como a decisão é tomada

1. **Permissão desconhecida.** Nega com `Reason::UnknownPermission`.
2. **Overrides.** Rodam em ordem, e o primeiro que responde decide. `override_except` tira permissões, e as que elas implicam, do alcance de um override.
3. **Coleta.** Um grant é candidato quando tudo isto vale:
   - a permissão dele é a pedida, ou uma que a implica;
   - o escopo dele está no caminho do recurso;
   - o alvo dele casa com um degrau do caminho;
   - o sujeito dele casa;
   - a condição dele é verdadeira.
4. **Estratégia.** A estratégia escolhe o grant que decide. Sem candidato, nega.

Uma condição ou relação que não pode ser avaliada (atributo ausente, motor sem `TupleStore`) nunca abre acesso: o `allow` é descartado, o `deny` continua valendo, e o motivo vai para `Decision::warnings`.

| Estratégia | Regra |
|---|---|
| `MostSpecific` (padrão) | Decide o degrau mais específico que tem algum grant; nesse degrau, `deny` vence. |
| `DenyOverrides` | Qualquer `deny` vence. |
| `PermitOverrides` | Qualquer `allow` vence. |
| `FirstApplicable` | Decide o primeiro grant na ordem da fonte. |

## Os três modelos

### RBAC

`RoleGraph::builder().inherit("maintainer", "member")` dá a `maintainer` os grants de `member`. `Subject::with_role_in(role, anchor)` limita um papel aos recursos abaixo daquele degrau.

### ABAC

`Grant::when(condition)` anexa uma `Condition` serializável. Os operandos leem `subject.*`, `resource.*` e `env.*`.

| Operadores | Sobre |
|---|---|
| `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `is_in`, `exists` | Qualquer valor |
| `starts_with`, `ends_with`, `contains` | Texto (`contains` também testa se um item está numa lista) |
| `any_in`, `all_in` | Listas |
| `ip_in` | Um endereço num CIDR ou numa lista de CIDRs |
| `time_between`, `weekday_in` | O instante da decisão, em UTC ou no fuso IANA `tz` |
| `all`, `any`, `not` | Outras condições |
| `call` | Uma função sua, registrada com `ConditionRegistry::register` |

As condições de tempo leem o instante dado por `Context::at`; sem ele não dá para resolvê-las, então o `allow` não vale. Não existe condição de expressão regular. `Engine::validate_grant` confere se cada `call` aponta para uma função registrada.

#### Fusos horários

Horário comercial é local, então `time_between` e `weekday_in` aceitam um fuso IANA opcional: `Condition::time_between("09:00", "18:00").in_tz("America/Sao_Paulo")` em Rust, `{"op": "time_between", "from": "09:00", "until": "18:00", "tz": "America/Sao_Paulo"}` em JSON ou JavaScript, e `time_between "09:00" "18:00" tz "America/Sao_Paulo"` ou `weekday_in ["mon", "tue"] tz "Europe/Lisbon"` na linguagem de política. Sem `tz` o relógio é UTC, como antes.

- **Horário de verão.** O instante decide a hora local. Uma janela dentro da hora que o avanço do relógio pula nunca vale naquele dia; a hora que a volta repete vale nas duas passagens. A janela que cruza a meia-noite (`"22:00"` a `"06:00"`) e o dia da semana seguem a data local.
- **Nomes desconhecidos.** O validador recusa um fuso que não conhece quando a política é carregada, com posição e dica. Uma condição montada sem validação falha na avaliação, e um `allow` com erro nunca se aplica.
- **Rastro.** O `explain` mostra a hora local usada, por exemplo `12:30 America/Sao_Paulo (UTC-03:00)`.
- **Custo.** O banco de fusos é a feature `tz`, ligada por padrão, do crate `strig` (`chrono-tz`) e soma cerca de 0,9 MB (0,13 MB com gzip) ao `.wasm`. Sem a feature, um `tz` é recusado na carga.

### ReBAC

Guarde tuplas `object#relation@subject` num `TupleStore` e descreva cada tipo num `RelationSchema` com `This`, `Computed`, `TupleToUserset`, `Union`, `Intersection` e `Exclusion`. `user:*` vale para todo usuário.

Um grant com `SubjectMatcher::relation("editor")` vale para quem tem `editor` no degrau em que o alvo dele corresponde. A busca para em `max_relation_depth` (32 por padrão) e corta ciclos.

## Governança

`Governance` passa uma mudança de grant por uma lista de invariantes e só devolve o novo conjunto de grants se todos passarem. Persista o resultado no `Ok`; no `Err` vêm as violações.

Daqui em diante, os trechos reaproveitam o `engine`, os `grants` e os sujeitos dos exemplos anteriores; nomes como `actor`, `current` (os grants que você tem hoje) e `request_meta` representam valores seus. O argumento `None` é um `TupleStore` opcional para ReBAC, e `apply_with` é o `apply` com metadados da requisição para a auditoria.

```rust
let governance = Governance::new()
    .with(CatalogConformance)
    .with(RequirePermission::new("org.roles.edit", org_resource.clone()))
    .with(NoSelfManagement)
    .with(NoLockout::new(["org.invite"], members, org_resource))
    .with(Forbid::new(SubjectMatcher::principal(AUTHENTICATED), ["project.delete"]))
    .audited(auditor);

let next = governance.apply_with(&engine, &actor, &current, &Mutation::Add(grant), None, &request_meta)?;
// persista `next`
```

Atribuir ou revogar um papel passa pelos mesmos invariantes e vai para a auditoria como `role_assign` ou `role_revoke`. O conjunto de grants volta igual; o sujeito a persistir vem de `Mutation::subject_after`.

```rust
let change = Mutation::AssignRole { subject: bob, role: RoleAssignment::in_scope("editor", org) };
governance.apply_with(&engine, &actor, &current, &change, None, &request_meta)?;
let bob = change.subject_after().expect("role change"); // persista os papéis do bob
```

`Forbid` só se aplica a uma atribuição de papel quando ela é para um usuário, e ignora o escopo. Escreva sua própria regra implementando `Invariant`. A lista de invariantes também pode vir de JSON (`InvariantSpec`).

### Aprovar uma mudança antes de aplicar

Uma mudança que a política marca como dependente de aprovação não é aplicada na hora: espera como pedido pendente, que outro ator aprova ou recusa. A política é por tipo de mudança e diz quem aprova.

```rust
let policy = ApprovalPolicy::new()
    .require(MutationKind::Add, "org.approve", org_resource.clone())
    .require(MutationKind::AssignRole, "org.approve", org_resource);
let store = MemoryPendingStore::new();
let flow = Approvals::new(&governance, &policy, &store);
let review = Review { engine: &engine, current: &current, tuples: None, now, meta: &request_meta };

// Ana propõe; as invariantes julgam e, se aceitam, o pedido fica guardado (expira em uma hora).
let Proposed::Pending(request) = flow.propose(&review, &ana, &Mutation::Add(grant), "req-1", Some(now + 3_600_000))? else {
    unreachable!("a política cobre Add");
};

// Caio aprova: precisa de `org.approve`, não pode ser a Ana, e as invariantes rodam de novo sobre `current`.
let approved = flow.approve(&review, &caio, &request.id)?;
// persista `approved.grants`
```

Quem aprova sendo o autor, sem a permissão, ou diante de invariantes que agora recusam recebe `ApprovalError::Refused` e o pedido segue pendente; `reject(&review, &caio, id, "motivo")` fecha com um motivo, e `expire_due(now, &meta)` fecha os que venceram (aprovar um pedido vencido também o fecha). Com auditor na governança, cada passo é um registro (`mutation_propose`, `mutation_approve`, `mutation_reject`, `mutation_expire`; veja [`docs/audit-format.md`](docs/audit-format.md)), e o registro da aprovação é gravado antes de a mudança ser aplicada. A crate não tem relógio nem banco: passe o instante e serialize as aprovações de um mesmo pedido quando vários processos dividem um store. Fora do escopo: vários aprovadores (quórum) e o autor retirar o próprio pedido.

Em JavaScript o engine julga e audita cada passo e o `Approvals` guarda os pedidos:

```js
import { Approvals, MemoryPendingStore } from '@the-hades-organization/strig/approvals';

const flow = new Approvals(engine, new MemoryPendingStore(), {
  approval: [{ kind: 'add', permission: 'org.approve', resource: orgResource }],
  invariants,
});
const proposed = await flow.propose(ana, { add: grant }, grants, { id: 'req-1', expiresAt: Date.now() + 3_600_000 });
const done = await flow.approve('req-1', caio, grants, { persist: (r) => saveGrants(r.grants) }); // `persist` roda antes de o pedido ser marcado como aprovado
await flow.reject('req-2', caio, 'fora da janela de mudança', grants);
await flow.expire();
```

O `JsonFileStore` guarda os pedidos no mesmo arquivo (`new Approvals(engine, store.pendingStore, options)`, e `store.approvePending(flow, id, approver)` grava as grants antes de marcar o pedido como aprovado). Sem regra para o tipo, `propose` aplica a mudança na hora (`applied: true`).

### Ver o impacto de uma mudança antes de aplicar

`Governance::apply` diz se a mudança passa nas invariantes, não o que ela faz com o acesso. `Governance::impact` responde isso sem aplicar nada: julga a mudança como o `apply` (uma mudança recusada devolve as violações), pergunta o mesmo sobre os grants antes e depois e devolve um `Impact`: quem ganha, quem perde, qual permissão, em qual recurso (e campo).

```rust
let options = ImpactOptions::new(ImpactSource::sample(
    SampleSpec::new().subject(bob).resource(project),
)); // ou ImpactSource::derived()
let impact = governance.impact(&engine, &ana, &current, &Mutation::Add(grant), &options)?;
for change in &impact.gained { /* change.subject, change.permission, change.resource */ }
```

As perguntas vêm de uma de duas fontes. A **amostra** é sua: sujeitos × recursos × permissões (e campos); sem recursos ou permissões, valem os que a mudança alcança e toca. A **derivada** usa as consultas reversas (`who_can_on`, `list`, `access_of`), restrita às permissões que a mudança toca, com as que as implicam (`implied_by`) e as que dependem delas (`depends_on`). Um deny que recorta, um override e um campo contam como em `check`. `ImpactOptions` recebe as tuplas, o `env`, os `QueryLimits` e um instante; quando um limite corta, `partial` é `true` e `notes` diz qual, então a ausência na lista não prova nada. O que não se decide (condição ou override que não dá para avaliar) fica em `indeterminate`, nunca em `gained`: só é ganho o que era um deny certo e agora é allow.

`Governance::apply_with_impact` aplica e devolve os grants com o impacto; com auditor em `detailed` ou `forensic`, o registro leva `impact` (contagens e até 10 exemplos, veja [`docs/audit-format.md`](docs/audit-format.md)). `Approvals::with_impact(&options)` guarda o impacto no pedido pendente ao propor; `approve` recalcula sobre os grants do momento (`Approved::proposed_impact` guarda o primeiro) e `review_impact` mostra os dois ao aprovador, e se diferem, antes de decidir. O store JSON guarda o pedido inteiro, então stores antigos abrem sem mudança.

Em JavaScript, `engine.impact(input)` recebe a entrada do `apply` mais `impact: { source, env, limits }`, o `apply` com `impact` devolve o resultado em `result.impact`, e `Approvals` aceita `impact` nas opções e tem `reviewImpact(id, current)`; o binding Python tem `engine.impact` e `engine.review_impact`, e os de Go e JVM, `Impact`/`ReviewImpact`.

```js
const preview = engine.impact({
  actor: ana, current: grants, mutation: { add: grant },
  impact: { source: { kind: 'sample', subjects: [bob], resources: [project] } },
});
if (preview.ok) console.log(preview.impact.gained, preview.impact.lost, preview.impact.partial);
```

### Elevação temporária e break-glass

Uma elevação é um papel ou uma permissão mantidos por um tempo. Ela anda sobre o fluxo de aprovação: a política diz, por papel ou permissão, quanto pode durar, quem aprova, se a justificativa é obrigatória e se o ator pode tomá-la numa emergência (break-glass).

```rust
let target = ElevationTarget::permission("project.edit", TargetSelector::exact("project", "p1")).scoped(org());
let policy = ElevationPolicy::new().with(
    ElevationRule::new(target.key(), 4 * HOUR, "org.approve", org_resource)
        .requiring_justification()
        .allowing_break_glass(HOUR), // nunca além do máximo da própria regra
);
let flow = Elevations::new(&governance, &policy, &store); // + .with_impact(&options)

// Ana pede; fica à espera de um aprovador.
let Elevated::Pending(request) = flow.request(&review, &ElevationRequest::new("e1", ana, target, 2 * HOUR).justified("incidente 42"), None)? else { unreachable!() };
// Caio aprova: a janela é [aprovação, aprovação + 2h), nunca além do máximo.
let approved = flow.approve(&review, &caio, "e1")?; // persista approved.grants
flow.revoke(&review, &ana, "e1", Some("terminei"))?; // antes do prazo, pelo ator ou por um aprovador
```

- **Aprovação.** `approve` é o `Approvals::approve` com a janela abrindo no instante da aprovação: a elevação vira um grant allow `elevation:<id>` ou uma atribuição de papel com `valid_from` e `valid_until`, e o motor a descarta no instante, sem job. O autor nunca aprova o próprio pedido, as invariantes rodam de novo sobre `current` e o impacto (`with_impact`) fica no pedido, como em qualquer mudança. Uma política que apertou depois do pedido recusa a aprovação que passaria do novo máximo. Prazo além do máximo, justificativa ausente e papel ou permissão que a política não lista são recusados no pedido.
- **Break-glass.** `ElevationRequest::break_glass()` só vale onde a regra tem `allowing_break_glass`, com máximo próprio e mais curto e uma justificativa. O ator o aprova sozinho: vale na hora, marcado como `break_glass` e com a revisão `pending`. Exige auditor em `forensic`, e seus registros são gravados com `FailMode::Closed` seja qual for a chamada, a permissão ou o auditor: se o sink falha, a elevação é negada. Outro ator que tenha a permissão de aprovador fecha a revisão com `close_review` (registro `elevation_review`, também forensic e fechado); `pending_reviews()` lista o que está aberto. O ator não fecha a própria.
- **Revogação e renovação.** `revoke` tira o grant ou o papel pela governança e guarda a `Revocation` no pedido. Renovar é um novo pedido.
- **Onde fica.** A elevação é o campo `elevation` do `PendingRequest`, então os stores não mudam de esquema. Um pedido já decidido recebe a revogação ou a revisão por `PendingStore::annotate` (a decisão não é tocada); implemente-o no seu store, o padrão recusa. `Elevations::active(now)` lista o que está em vigor.
- **Tempo real.** No `strig-sync`, `hub.elevation_approved(&request, now)` publica o `Change` da elevação e agenda o aviso de expiração em `valid_until` (o mesmo mecanismo das janelas que o `CapabilityCache` acompanha); `hub.elevation_revoked(&request)` publica a revogação.
- **Escolhas a conhecer.** A revogação é julgada pelas invariantes como quem revoga, então uma invariante como `NoSelfManagement` pode recusar a auto-revogação. Um pedido para papel ou permissão que a política não lista é tentativa de escalada: é recusado com a violação `not_in_policy` e auditado (`mutation_propose`, resultado `rejected`, `refusal: not_in_policy` nos metadados) no nível do auditor, sem precisar de regra; um sink que falha em modo `closed` vira recusa por `audit`. Um `revoke` recusado sobre um pedido que não é elevação, não está aprovado, já foi revogado ou já terminou não deixa registro. O `annotate` roda depois de o grant ser aplicado: se falhar, o grant já saiu e o pedido fica sem a marca, então o chamador guarda os grants que recebeu.

Em JavaScript, `Elevations` (`@the-hades-organization/strig/approvals`) guarda os pedidos sobre um `PendingStore` que tenha `annotate` (`MemoryPendingStore` e `JsonFileStore.pendingStore` têm) e chama `engine.elevate(input)`, que também existe em Python (`engine.elevate`) e na ABI Wasm (`elevate`):

```js
const flow = new Elevations(engine, store.pendingStore, {
  elevation: [{ key: { permission: 'project.edit' }, maxDurationMs: 4 * HOUR, approverPermission: 'org.approve', approverResource: orgResource, requireJustification: true, breakGlass: { maxDurationMs: HOUR } }],
  invariants,
  audit: { level: 'forensic' },
});
await flow.request({ id: 'e1', actor: ana, target, durationMs: 2 * HOUR, justification: 'incidente 42' }, grants);
await flow.approve('e1', caio, grants, { persist: (r) => saveGrants(r.grants) });
await flow.revoke('e1', ana, grants, { reason: 'terminei', persist: (r) => saveGrants(r.grants) });
await flow.closeReview('e2', caio, 'uso legítimo', grants); // depois de um break-glass
```

### Separação de funções

O catálogo declara o que ninguém acumula e o que ninguém faz duas vezes no mesmo recurso.

```rust
let catalog = Catalog::builder()
    .target_kinds(["org", "payment"])
    .permission(PermissionDef::new("payment.create").targets(["payment"]))
    .permission(PermissionDef::new("payment.approve").targets(["payment"]))
    // estática: ninguém tem os dois papéis dentro da mesma org
    .mutually_exclusive(MutualExclusion::new("payment_duties", ExclusiveKind::Roles, ["maker", "checker"]).per_anchor("org"))
    // dinâmica: quem criou o pagamento não o aprova
    .conflicting_actions(ActionConflict::new("four_eyes", ["payment.create"], ["payment.approve"]))
    .build()?;
let governance = Governance::new().with(SeparationOfDuties::new());
```

**Estática.** Um conjunto `mutually_exclusive` lista papéis ou permissões, com nome e escopo: global, ou
`per_anchor("org")` para conflitar só dentro do mesmo anchor. O invariante `SeparationOfDuties` recusa a mudança que
criaria um acúmulo que não existia, seja qual for o caminho até o membro: papel direto, herdado (`RoleGraph`), grant ou
elevação temporária. A `Violation` nomeia o conjunto e os dois lados. Remover e revogar nunca criam conflito, então um
conjunto já violado sempre pode ser consertado; um `deny` nunca é lido como tirar um membro. `with_subjects` acrescenta
sujeitos contra cujas posses um grant adicionado também é julgado. O `Impact` lista em `separation` os conflitos que a
mudança criaria, com o invariante ligado ou não, e o `strig lint` aponta os conjuntos já violados (`L009`).

**Dinâmica.** Uma regra `conflicting_actions` diz que quem fez uma ação `first` em um recurso não faz uma ação `then`
nele. O motor avalia em toda decisão, antes dos overrides e sem IO: o histórico é um atributo do recurso (`history` por
padrão, ou o que a regra nomear) ou do `env`, uma lista de entradas `"<permissão>:<ator>"` (`"payment.create:ana"`). A
negação vem como `Reason::Override` de nome `separation:<regra>`. Com `distinct_roles`, a entrada também leva os papéis
com que o autor agiu (`"payment.create:ana|maker"`) e quem tem um deles é recusado também; entrada sem papéis recusa, e
histórico ilegível também: a regra falha fechada. Listagem e consulta reversa nunca deixam a regra abrir nada: para uma
permissão de `then` a resposta continua um resíduo.

No fluxo de aprovação, `Approvals::with_distinct_roles()` também recusa o aprovador que divide um papel com o autor,
além de o autor nunca aprovar o próprio pedido.

Na linguagem de políticas são `mutually_exclusive` e `conflicting_actions` no catálogo e o invariante
`separation_of_duties`; veja [docs/dsl.pt-BR.md](docs/dsl.pt-BR.md). Uma política que os usa exporta `"schema": 5`.

### Regras declaradas no catálogo

Algumas regras pertencem a uma permissão, então são declaradas no `PermissionDef` dela:

| Flag | Efeito |
|---|---|
| `depends_on` | Ter a permissão exige ter cada uma das listadas no mesmo recurso (conferido por `Prerequisites`). |
| `non_delegable` | Só um gestor a concede, não qualquer um que apenas a tenha. |
| `management_only` | Só pode ser concedida a papéis de gestão. |
| `override_only` | Só vale por um override; um grant comum dela não conta. |

`NoEscalation` impede alguém de conceder o que não tem: grants `allow` e atribuições de papel são recusados a menos que o autor tenha cada permissão que eles conferem, e cada permissão que essas implicam, onde quer que eles valham. Ter `org.roles.edit`, portanto, não serve para dar a alguém um papel mais forte que o seu.

```rust
let catalog = Catalog::builder()
    .target_kind("project")
    .permission(PermissionDef::new("project.view").targets(["project"]))
    .permission(PermissionDef::new("project.edit").targets(["project"]).depends_on(["project.view"]))
    .permission(PermissionDef::new("project.share").targets(["project"]).non_delegable())
    .permission(PermissionDef::new("project.purge").targets(["project"]).override_only())
    .build()?;
let engine = Engine::builder(catalog).build()?;

let governance = Governance::new()
    .with(CatalogConformance)
    .with(Prerequisites)
    .with(NoEscalation::new());

// `lead` só tem `project.edit`, então conceder `project.view` é escalada.
let current = vec![Grant::allow("l", SubjectMatcher::user("lead"), "project.edit", TargetSelector::kind("project"))];
let handout = Mutation::Add(Grant::allow("a", SubjectMatcher::user("ana"), "project.view", TargetSelector::kind("project")));
let refused = governance.apply(&engine, &Subject::user("lead"), &current, &handout, None).unwrap_err();
assert_eq!(refused[0].invariant, "no_escalation");
```

Mais duas ferramentas:

- **Reserva contra lockout.** `NoLockout::with_reserve` diz quem deve assumir uma permissão crítica. Quando uma mudança deixaria essa permissão sem ninguém, a `Violation` traz uma `Suggestion` com a atribuição de papel que resolve. Nada é aplicado; a sugestão também vai para o registro de auditoria.
- **Modelos de papel.** `RoleTemplate::materialize` transforma um modelo em grants comuns. O id e a versão do modelo vão nos metadados da mudança; os grants não guardam vínculo com o modelo.

## Auditoria

Com a feature `audit`, toda mudança que passa pela governança vira um `AuditRecord`, aplicada ou recusada. Registre tuplas ReBAC e atribuições de papel com `Auditor::tuple_change` e `Auditor::role_change`. Se o destino falha ao gravar, a governança recusa a mudança com a violação `audit`: sem registro, sem mudança (a menos que você escolha `FailMode::Open`, abaixo).

```rust
let auditor = Arc::new(Auditor::new(AuditLevel::Standard, Arc::new(JsonLinesAudit::new(file))));
```

Os destinos prontos são `MemoryAuditLog` e `JsonLinesAudit`, que escreve em qualquer `io::Write`. Para mandar os registros a um banco, uma fila ou um SIEM, implemente `AuditSink`.

### O que cada nível guarda

Cada nível guarda tudo do nível acima. Os tamanhos são bytes de JSON compacto por linha de JSON Lines, sem compressão nem índices, medidos num registro de referência (`audit::reference_record`): um grant com escopo e condição de duas cláusulas, ids UUID, um autor com dois papéis e três metadados da requisição.

| Nível | Registros de mudança guardam | Bytes | Por 1 milhão |
|---|---|---:|---:|
| `minimal` | Quando, quem, ação, id do objeto, resultado | 175 | 175 MB |
| `standard` | + resumo do grant (permissão, sujeito, alvo, efeito, escopo, se tem condição) e os nomes dos invariantes que recusaram | 388 | 388 MB |
| `detailed` | + o grant inteiro com a condição, o autor completo, as mensagens das violações, os metadados da requisição | 1.097 | 1,10 GB |
| `forensic` | + digest SHA-256 do conjunto de grants antes e depois, e a cadeia de hash | 1.415 | 1,42 GB |

Decisões também podem ser auditadas: `Auditor::decide(&engine, &ctx, &request, &meta)` decide e registra. A decisão de referência (`audit::reference_decision_record`) tem três grants na fonte, um deles com condição, um recurso com três degraus, ids UUID e três metadados.

| Nível | Registros de decisão guardam | Bytes | Por 1 milhão |
|---|---|---:|---:|
| `minimal` | Quando, sujeito, `permission@resource`, permitido ou negado | 285 | 285 MB |
| `standard` | + o motivo (override, grant e degrau que decidiram, ou nenhum grant) e os grants casados | 669 | 669 MB |
| `detailed` | + o sujeito e o recurso completos, os avisos, os metadados da requisição. O bastante para reavaliar a decisão depois | 1.239 | 1,24 GB |
| `forensic` | + o rastro completo de `Engine::explain`, e a cadeia de hash | 3.582 | 3,58 GB |

Para projetar o seu volume, chame `AuditLevel::estimate_bytes(n)` para mudanças e `AuditLevel::estimate_decision_bytes(n)` para decisões; o tamanho forense da decisão cresce com o número de grants que a fonte devolve. Num banco, some o overhead por linha (cerca de 28 bytes no Postgres) e os seus índices.

Os números são conferidos: os testes `estimates_match_reference_records` e `decision_estimates_match_reference_records` falham se um tamanho medido se afastar mais de 10% da tabela, e `cargo run -p strig --example audit_storage` mede de novo.

### Cadeia de hash

No nível `forensic`, cada registro leva o hash do anterior. `audit::verify_chain` detecta um registro editado ou removido, e `Auditor::resume_chain` continua a cadeia depois de um reinício.

Os bytes exatos de um registro e o cálculo do hash, com um vetor de teste que outra linguagem consegue reproduzir, estão em [docs/audit-format.md](docs/audit-format.md) (em inglês). A mesma página explica como pegar só os registros e encadear no seu próprio log, e como ancorar a cabeça da cadeia fora (`Auditor::chain_head`, depois `verify_chain_anchored(&records, start, head)`), que é o que pega registros cortados do fim.

### Verificável por terceiros

Uma cadeia de hash prova que o log está íntegro para quem tem o log inteiro. Três adições deixam um auditor conferir a trilha sem confiar no host, e nenhuma muda o registro nem o hash dele:

- **Provas Merkle** (`strig::merkle`, feature `audit`): os registros são as folhas de uma árvore RFC 6962 / RFC 9162. `MerkleTree::from_records(&records)` dá a raiz, a prova de inclusão de um registro e a de consistência entre duas cabeças, para entregar um registro ou um trecho ao auditor sem o resto. `verify_inclusion` e `verify_consistency` são puras; em JS, `verifyMerkleInclusion({ record, index, size, proof, root })` e `verifyMerkleConsistency({ first, second, firstRoot, secondRoot, proof })`.
- **Carimbo de tempo RFC 3161** (feature `timestamp`, desligada por padrão; o núcleo sem ela não ganha dependência): `TimestampRequest::for_chain_head(head, nonce)` monta a requisição da cabeça, você a envia a uma TSA, e `timestamp::verify_response` (JS: `verifyTimestamp({ response, head, roots, nonce? })`, sem rede) confere o imprint, o nonce, a política, a assinatura e a cadeia de certificados contra as raízes que **você** fornece. Sem raiz, recusa tudo. `examples/timestamp_http.rs` envia a requisição com `curl`.
- **Relatório de conformidade**: `strig audit report trilha.jsonl --anchor-head <hash> --timestamp head.tsr --root ca.pem [--json]` resume o período, os registros por ação e resultado, as mudanças por ator, as recusas por invariante, as quebras de cadeia, as âncoras e os carimbos, e sai com `1` quando a trilha não está conforme. Os mesmos dados são `strig::audit_report::ConformanceReport`.

A árvore, o carimbo e os vetores de teste, reproduzíveis em outra linguagem, estão em [docs/audit-format.md](docs/audit-format.md).

### Quando o destino falha

Por padrão, um destino que falha recusa a mudança (`FailMode::Closed`). Com `FailMode::Open` a mudança segue e o registro espera numa fila de retentativa em memória, em ordem, com capacidade e backoff configuráveis (`RetryPolicy`); `AuditStatus::Pending` diz que está esperando e `Auditor::stats()` conta o que espera ou foi descartado. O modo vem da chamada (`governance.at(now).fail_mode(..)`, `Auditor::grant_mutation_with`), da permissão (`with_permission_fail_mode`) ou do padrão do auditor (`with_fail_mode`), nessa ordem de precedência.

```rust
let auditor = Auditor::new(AuditLevel::Forensic, sink)
    .with_fail_mode(FailMode::Closed)
    .with_permission_fail_mode("report.view", FailMode::Open)
    .with_retry(RetryPolicy { capacity: 500, ..RetryPolicy::default() })
    .with_redactor(mask_attributes(["ip", "email"], "[redacted]"));
```

`with_redactor` mascara atributos antes de o registro ser hasheado e gravado, então o hash cobre a versão mascarada.

Em JS o destino é uma função síncrona; um `throw` é falha do destino:

```js
const engine = new Engine(spec, {
  auditSink: (record) => log.append(record),
  auditPolicy: { failMode: 'closed', permissions: { 'report.view': 'open' }, capacity: 500 },
  onAuditDrop: (record) => spill.write(record),
});
const out = engine.apply({ actor, current, mutation, audit: { level: 'forensic', prevHash, failMode: 'open' } });
out.auditStatus;                 // 'written' | 'pending' | 'dropped'
engine.flushAudit();             // tenta a fila de novo e devolve { pending, writtenLate, dropped, failures, nextRetryAt }
verifyAuditChain(records, { start, head }); // { ok: true, head } ou { ok: false, code }
```

## Janelas de validade

`Grant::valid_between(from, until)` limita um grant no tempo; `valid_from` e `valid_until` definem uma ponta só.

- Os tempos são milissegundos desde a época Unix. A janela inclui `from` e exclui `until`.
- Quem chama fornece o instante: `Context::at(now)` nas decisões, `Governance::at(now)` nas mudanças.
- Sem instante, um grant com janela não vale, então relógio ausente nega.

```rust
let grant = Grant::allow("w", SubjectMatcher::user("ana"), "project.view", TargetSelector::kind("project"))
    .valid_between(1_000, 2_000);
let grants = vec![grant];
let ana = Subject::user("ana");
let project = Resource::new("project", "p1");
let request = Request::new(&ana, "project.view", &project);

assert!(engine.check(&Context::new(&grants).at(1_500), &request));
assert!(!engine.check(&Context::new(&grants).at(2_000), &request));
assert!(!engine.check(&Context::new(&grants), &request));
```

`CapabilityCache` expira as entradas no próximo limite de janela. Tirar do armazenamento os grants vencidos fica a cargo de um job seu.

## Permissão por campo

Um grant pode nomear os campos do recurso que cobre, como o CASL faz: "`document.edit` só em `title` e `body`". Um grant sem campos cobre o recurso inteiro, exatamente como antes.

```rust
let catalog = Catalog::builder()
    .target_kinds(["document"])
    .permission(PermissionDef::new("document.edit").targets(["document"]).fields(["title", "body", "status"]))
    .build()?;
let engine = Engine::builder(catalog).build()?;

let grants = vec![
    Grant::allow("edit", SubjectMatcher::role("editor"), "document.edit", TargetSelector::kind("document")),
    Grant::deny("freeze", SubjectMatcher::role("editor"), "document.edit", TargetSelector::kind("document"))
        .fields(["status"]),
];
let ana = Subject::user("ana").with_role("editor");
let doc = Resource::new("document", "d1");
let ctx = Context::new(&grants);

engine.allowed_fields(&ctx, &ana, "document.edit", &doc); // FieldSet::Only { title, body }
engine.check(&ctx, &Request::new(&ana, "document.edit", &doc).field("title")); // true
engine.check(&ctx, &Request::new(&ana, "document.edit", &doc).field("status")); // false
```

Como as peças se combinam:

- **Um campo é uma decisão.** A pergunta sobre um campo (`Request::field`) é decidida pela mesma estratégia (`MostSpecific`, `DenyOverrides`, `PermitOverrides`, `FirstApplicable`) sobre os grants que cobrem aquele campo. Um `deny` com campos tira só esses campos; um `allow` com campos dá só esses. Não há regra nova para aprender: cada campo é julgado como se os grants que não o nomeiam não existissem.
- **O recurso inteiro exige todos os campos.** A pergunta sem campo só é permitida por um grant sem campos, e um `deny` com campos a bloqueia assim que a estratégia negaria algum dos seus campos. Assim `check` continua seguro como portão: um `allow` restrito a campos nunca abre o recurso, e quem responde "quais campos" é o `allowed_fields`.
- **`implied_by` leva os campos.** Um grant de `document.manage` restrito a `title` dá `document.edit` só em `title`.
- **`depends_on` é julgado no mesmo campo.** `document.edit` em `body` exige `document.view` em `body` (ou no recurso inteiro).
- **O catálogo pode declarar os campos** de uma permissão. Aí um grant que nomeia outro campo é recusado por `validate_grant` (e pelo validador de política, com a linha e uma dica), e o pedido de um campo não declarado é negado. Sem declaração, o motor confia nos nomes que os grants usam, e `allowed_fields` pode responder `AllExcept` ("tudo menos `status`"), já que não consegue listar o resto.
- **Falha fechada.** Condição que não pode ser avaliada derruba um `allow` e mantém um `deny`, campo a campo. Um override que permite dá todos os campos.
- **Política sem campos decide como sempre decidiu.** Os testes fixam isso.

`Engine::explain_fields` devolve, por campo, os grants que o deram e os que o tiraram; `Engine::explain` de um pedido com campo marca os grants que não o cobrem (`FieldNotCovered`). As listagens (`list`) e o `who_can` respondem pelo recurso inteiro: um `allow` restrito a campos fica de fora e um `deny` restrito a campos conta como um comum.

A governança acompanha: `NoEscalation` recusa dar um campo que o ator não tem (e um grant do recurso inteiro a quem só tem alguns campos), e `CatalogConformance` valida os campos contra o catálogo.

Na linguagem de políticas, `fields` é um campo de `permission` e de `grant` nas três sintaxes (`fields = [title, body]` em Blocks, `fields title, body` em Rules e Actors). A política que usa campos exporta `"schema": 4`, então um leitor de schema mais antigo a recusa em vez de ler um grant restrito a campos como um do recurso inteiro. Veja [docs/dsl.pt-BR.md](docs/dsl.pt-BR.md).

Em JavaScript, `engine.allowedFields(ctx, request)` devolve `{ kind: 'all' | 'all_except' | 'only' | 'none', fields? }`, `request.field` pergunta por um campo e `pickAllowed(objeto, fields)` mascara uma resposta:

```ts
const fields = engine.allowedFields(ctx, { subject, permission: 'document.edit', resource });
res.json(pickAllowed(document, fields)); // só title e body saem
```

`PermissionClient.allowedFields(permission, resource)` e `can(permission, resource, field)` decidem localmente. As capacidades que carregam grants restritos a campos vão em duas formas (`grants` para leitores antigos, que nunca veem um `allow` restrito e leem um `deny` restrito como inteiro, e `withFields` com os reais), então um cliente antigo falha fechado.

## Por que não? O que permitiria

`Engine::explain` diz por que uma decisão saiu como saiu. Quando é uma negação, `Engine::why_not(ctx, request, options)` acrescenta o que a transformaria em `allow`: as menores mudanças, a menor e mais específica primeiro. Devolve `None` quando o pedido já é permitido.

```rust
let resposta = engine.why_not(&ctx, &request, &WhyNotOptions::default()).expect("negado");
println!("{:?}", resposta.cause); // o que negou: Cause::NoApplicableGrant, Cause::Deny { .. }, Cause::Override { .. }, ...
for remedio in &resposta.remedies {
    println!("{:?} {:?}", remedio.change, remedio.caveats);
}
```

| Mudança | Significado |
|---|---|
| `SatisfyCondition` | um `allow` que seria aplicável tem uma condição que falhou (`failed`, com os valores que o motor viu) ou que não pôde ser avaliada (`unresolved`, um atributo ausente, por exemplo). Nenhum valor é inventado: ela nomeia o que precisa valer. |
| `AddGrant` | um `allow` para o sujeito no passo mais específico do caminho (o alvo exato e depois o tipo), conferido com `validate_grant`, então respeita os `targets` e `fields` do catálogo; uma pergunta por campo pede só aquele campo |
| `NarrowDeny` | tirar o campo perguntado dos `fields` do `deny` que decidiu |
| `AssignRole` | um papel que tem um `allow` aplicável, com escopo no passo mais estreito do caminho |
| `RemoveDeny` | remover o `deny` que decidiu |

Cada remédio é **verificado**: o motor o aplica sozinho sobre uma cópia do sujeito ou dos grants e decide o pedido de novo. Só volta a mudança que resulta em `allow`, então uma sugestão que não funcionaria (um papel barrado por um deny, um grant que a estratégia `DenyOverrides` ainda vence) não aparece. Nada é gravado.

- Uma negação por **override** (conta suspensa, por exemplo) volta como `Cause::Override { name }` sem remédio: nenhuma mudança de grants ou papéis a desfaz. O mesmo vale para `UnknownPermission` e para uma permissão `override_only` (`Cause::OverrideOnlyPermission`). Quando o que falta é um pré-requisito (`depends_on`), a causa diz qual, com a causa do pré-requisito, e os remédios são para o pré-requisito.
- Cada remédio leva `caveats` para a governança que o catálogo conhece (`ManagementOnly`, `NonDelegable`, `OverrideOnly`) e `AffectsOthers` quando a mudança edita um grant que não é do próprio sujeito. As invariantes de uma `Governance` não são consultadas: a mudança ainda pode ser recusada ao ser aplicada.
- Grants de outros sujeitos nunca são listados: só o `deny` que decidiu é nomeado, e só o `allow` de um papel serve para sugerir esse papel.
- `WhyNotOptions` limita o trabalho: `limits.max_decisions` limita as verificações (o motor não tem relógio, então o limite é uma contagem, como nas consultas reversas) e `max_remedies` a lista (16 por padrão). Quando um deles corta a resposta, `partial` é verdadeiro.
- As mudanças são únicas: uma negação que exige duas mudanças ao mesmo tempo (um allow que também é vencido por um deny) mostra a remoção do deny só se ela bastar sozinha.

Em JavaScript e Python: `engine.whyNot(ctx, request, now?, options?)` e `engine.why_not(ctx, request, now=None, options=None)`, com `options = { maxDecisions, maxRemedies }` (os limites do `Context` valem por padrão); `null`/`None` quando permitido. Os valores são JSON com os mesmos nomes em camelCase; `Remedies`, `Remedy` e a causa têm tipos em `index.d.ts`. A ABI Wasm tem a operação `whyNot`. `strig-inspect explain` imprime os remédios depois de uma negação.

## Consultas reversas e listagem filtrada

Pergunte quem pode fazer algo, ou o que um sujeito alcança, em vez de checar uma requisição. `QueryContext` leva os grants (e `.at(now)`), `QueryLimits` limita o trabalho e `PgTables` transforma as respostas em SQL.

```rust
let qctx = QueryContext::new(&grants).at(1_500);
let filter = engine.list(&qctx, &ana, "project.view", "project");
let who = engine.who_can(&qctx, "project.view");
assert_eq!(who, vec![SubjectRef::User { id: "ana".into() }]);
```

| Chamada | Devolve |
|---|---|
| `engine.list(&qctx, &subject, permission, kind)` | Um `AccessFilter` sobre os recursos daquele tipo que o sujeito alcança, pronto para virar uma cláusula `WHERE`. |
| `engine.who_can(&qctx, permission)` | Todos os nomeados por um grant `allow` da permissão, em qualquer lugar. Denies, overrides e condições não são avaliados. |
| `engine.who_can_on(..)` | O mesmo num recurso, com denies, overrides e condições avaliados. |
| `engine.access_of(..)` | Todos com acesso a um recurso, e as permissões de cada um. |
| `engine.check_for(..)` | Uma checagem por referência de sujeito: um `SubjectResolver` carrega o sujeito, e a resposta diz o caminho que decidiu. |

## Recurso exclusivo

Com a feature `exclusive`, um recurso pode ter um detentor por vez. `Terms::new(priority, ttl_ms)` define a força do pedido e quanto ele dura. Uma prioridade maior só toma o recurso quando quem pede também tem `exclusive.preempt`. Permissões e tempo são conferidos pelo mesmo motor de qualquer outra decisão.

```rust
let mut registry = ExclusiveRegistry::default();
let now = 0; // milissegundos desde a época Unix, passados por quem chama
let first = registry.acquire_checked(&engine, &ctx, &ana, &document, Terms::new(1, 60_000), now)?;
assert_eq!(first, Acquisition::Granted);

let second = registry.acquire_checked(&engine, &ctx, &bob, &document, Terms::new(9, 60_000), now + 10)?;
assert!(matches!(second, Acquisition::Preempted { .. }));
```

### Entre processos

`ExclusiveRegistry::default()` guarda as posses na memória, então o recurso é exclusivo dentro de um processo. Para dividi-lo entre instâncias, dê ao registro um store que decide de forma atômica no banco:

```rust
// Postgres: rode `migrate_with` antes (a versão 4 do esquema cria `<prefixo>_exclusive`).
let store = PgExclusiveStore::connect(&url, PgTables::default()).await?;
let mut registry = ExclusiveRegistry::new(store);

// Redis: toda instância que divide o recurso usa o mesmo prefixo.
let mut registry = ExclusiveRegistry::new(RedisExclusiveStore::new("redis://127.0.0.1/", "strig:exclusive")?);
```

Adquirir, renovar, liberar e a varredura (`expire`) são um passo atômico em cada store: trava de linha numa transação no Postgres, `WATCH`/`MULTI`/`EXEC` no Redis. Duas instâncias disputando o mesmo recurso têm exatamente um vencedor. Os dois dão as mesmas respostas do store em memória (`strig::exclusive_conformance::run` (feature `conformance`) é a bateria que todo store passa), e a posse estar ativa é sempre decidido com o `now` que você passa, nunca com o relógio do banco. No Redis a expiração nativa só devolve memória, depois da vida da posse mais uma retenção (uma hora por padrão). O trait é síncrono: os dois stores bloqueiam quem chama pelo tempo da ida e volta (use `spawn_blocking` dentro de uma task async) e falham fechado com `StoreError` em timeout ou conexão perdida. O Postgres mantém a conexão numa thread própria, como o `PgPendingStore`; o Redis usa a conexão síncrona do crate `redis` com timeouts. Os dois crates têm a feature `exclusive`, ligada por padrão. O binding JavaScript ainda não os expõe.

## Tempo real

```text
mudança de grant ──► Hub::publish ──► sessões locais (SSE/WebSocket) e CapabilityCache
                          │
                          └─► Transport (Redis, Postgres, o seu) ──► Hub nas outras instâncias
```

```rust
let hub = Hub::builder()
    .transport(RedisTransport::new("redis://127.0.0.1/", "strig:changes")?)
    .build();
let _relay = hub.spawn_relay();

let cache = Arc::new(CapabilityCache::new(Duration::from_secs(30), 10_000));
hub.on_change(cache.clone());
let provider = EngineProvider::new(engine, my_grant_loader).with_cache(cache);
let realtime = strig_axum::Realtime::new(hub).with_provider(Arc::new(provider));
// nas rotas: realtime.sse(subject, scopes) ou realtime.websocket(upgrade, subject, scopes)
```

O aviso de mudança (`Change`) diz o tipo de mudança e em qual degrau, sem os grants. Quem recebe recarrega da própria fonte, então qualquer transporte serve.

Uma sessão observa escopos, isto é, âncoras como `org:acme`. Com um `CapabilityProvider`, ela envia ao cliente as capacidades (as permissões que o sujeito tem) de cada escopo afetado, e mudanças que chegam juntas são recalculadas uma vez só. Quando o transporte cai e volta, ou um cliente fica para trás, o hub emite `Resync` e tudo é recarregado.

| Transporte | Crate | Observações |
|---|---|---|
| Redis | `strig-redis` | Pub/sub; a publicação reconecta sozinha. |
| Postgres | `strig-postgres` | `LISTEN/NOTIFY`. Chame `strig_postgres::notify(&tx, channel, &change)` dentro da transação que grava o grant, e o aviso só sai no commit. TLS via `PgTransport::with_tls`. |
| O seu | | NATS, Kafka ou qualquer broker: implemente `Transport` (`publish` e `subscribe`). |

O protocolo do cliente é JSON e igual em SSE e WebSocket. O servidor envia `hello`, `capabilities`, `change`, `resync`, `error` e `ping`; o cliente envia `watch`, `unwatch` e `refresh` (só WebSocket). Para um framework web que não seja o axum, repasse o stream de `Session::open` e escreva cada mensagem com `ServerMessage::to_sse` ou `to_json`.

### Ler a própria escrita

Depois de uma mudança, nenhuma instância nem cliente deve decidir com estado mais velho que ela. Cada mudança aceita ganha uma **revisão**: um texto opaco e serializável `escopo@valor` que só cresce dentro de um escopo de dados (o escopo nomeia os dados que um contador ordena, por exemplo um tenant). Quem atribui é o store: `Governance::with_revisions(Arc<dyn RevisionSource>)` para os stores de memória e arquivo (`MemoryRevisions`), ou `strig_postgres::next_revision(&tx, "minha_sequence", "tenant")` dentro da transação que grava a mudança, de modo que a revisão confirma junto com ela. `apply_revised` e `apply_with_impact` a devolvem (`Revised`, `AppliedWithImpact::revision`), e `Change::with_revision` a leva no aviso.

```rust
let applied = governance.apply_revised(&engine, &actor, &grants, &mutation, None, &Attributes::new())?;
let revision = applied.revision.expect("há uma fonte configurada");   // "tenant@42"
// entregue a quem lê em seguida: um header, um cookie, a resposta da escrita

let provider = EngineProvider::new(engine, loader)
    .with_cache(cache)
    .with_consistency(ConsistencyOptions::default().timeout(Duration::from_secs(1)));
// provider.evaluate_revised(&subject, &scope, Some(&revision)) recarrega, ou espera o Change, até o timeout
```

Uma instância atrás recarrega (ou espera o `Change`) até o timeout e, sem chegar lá, **nega com motivo próprio**: `revision_not_reached`, `revision_scope_mismatch` (token de outro escopo), `revision_untracked` (a fonte não sabe dizer a própria revisão) ou `source_unavailable`. Nunca decide com estado mais velho. O `CapabilityCache` guarda a revisão de cada entrada (`get_at_least`, `insert_revised`).

- **Protocolo do cliente (versão 2, aditivo).** `hello` leva `version`, `capabilities` leva a `revision` dos dados de que o conjunto foi calculado, `change` leva a `revision` da escrita, e o cliente pode enviar `refresh_at_least` com uma revisão; o escopo que não alcança essa revisão recebe um `error` (`revision_not_reached`, ...), nunca um conjunto mais velho. No SSE, que não tem canal de volta, o cliente reconecta com `?min_revision=` e o endpoint repassa à sessão.
- **Servidor de decisão.** O `/v1` aceita o token no header `x-strig-min-revision` em toda rota, e no campo `min_revision` de `check` e `check/batch`. Uma fonte atrás dele responde `503` com `revision_not_reached` (ou `revision_mismatch`, para outro escopo); as respostas trazem a `revision` de que saíram. Essas recusas não contam contra o circuit breaker do cliente. Em Rust: `Client::check_at_least` e `check_batch_at_least`; `Snapshot::with_revision` na fonte.
- **JavaScript.** `new PermissionClient({ ..., minRevision: 'tenant@42' })` ou `client.requireRevision(rev)` depois de uma escrita: até as capabilities alcançarem, toda decisão nega (`client.behind()`, `client.revision(escopo)`). Os bindings de React e Angular expõem o estado: `useStrigStatus().behind` e `useRequireRevision()`, `StrigService.status().behind` e `requireRevision()`. O `RemoteClient` aceita `minRevision` nas opções, por `check` ou por `checkBatch(requests, { minRevision })`, envia o header e nega a resposta que não prova a revisão, então um servidor que ignora o pedido não faz o cliente passar. `openSession` aceita `revision` (o que esta instância carregou) e `minRevision`.

## Armazenamento em Postgres

O `strig-postgres` também guarda os dados no Postgres: grants, tuplas ReBAC, atribuições de papel e pedidos pendentes, atrás dos mesmos traits que o motor já lê (`GrantSource`, `GrantIndex`, `TupleStore`, `TupleIndex`, `PendingStore`).

```rust
use strig_postgres::{PgPendingStore, PgStore, PgTables, connect, migrate_with};

let tables = PgTables::default().in_schema("authz")?.with_prefix("strig")?; // schema e nomes são seus
let client = connect(&url).await?;
migrate_with(&client, &tables).await?; // idempotente, versionada, segura em todo boot

let store = PgStore::load(&client, tables.clone()).await?;
let grants = store.grants(); // GrantSource + GrantIndex, servido da memória
let tuples = store.tuples(); // TupleStore + TupleIndex
let _follower = store.follow(hub.subscribe(), move || connect(&url), Duration::from_secs(1));
```

- **Por que um snapshot.** O core não faz IO e o `GrantSource` é síncrono, então `PgStore::load` lê as tabelas e o motor é servido da memória. O snapshot recarrega quando o transporte entrega um `Change` (grants, tuplas ou resync; um receptor atrasado recarrega tudo). O store só existe carregado, então o motor nunca decide sobre um conjunto vazio que estaria sem um deny. Se uma recarga falha, o snapshot anterior fica e `is_stale()` vira verdadeiro: ligue-o à sonda de readiness. O snapshot guarda todos os grants e tuplas, então dimensione para isso; para conjuntos de tuplas muito grandes, continue respondendo o `TupleStore` com a sua própria consulta indexada.
- **Escrita.** `put_grant`, `delete_grant`, `put_tuple`, `delete_tuple`, `assign_role` e `revoke_role` recebem um cliente ou uma transação. `commit_mutation(&tx, channel, &mutation)` grava o que uma `Mutation` muda e envia o `NOTIFY` na mesma transação, então o aviso sai se, e só se, a mudança der commit. Chame `lock_governance(&tx)` primeiro e leia `all_grants(&tx)` dentro da transação, para que duas instâncias não julguem uma mudança sobre o mesmo conjunto desatualizado.
- **Governança ponta a ponta.** Leia os grants e o ator (`tables.subject(&tx, "user", id)` monta o `Subject` com os papéis gravados), rode `Governance::apply`, depois `commit_mutation` e o commit. As outras instâncias recarregam com o aviso.
- **Papéis.** `strig_roles` guarda as atribuições por sujeito (papel, escopo opcional, janela opcional). Um sujeito lido dela carrega o principal `authenticated` quando o tipo é `user`.
- **Pedidos pendentes.** `PgPendingStore` é um `PendingStore` sobre uma tabela, com a expiração numa coluna indexada (`due(now)` lista o que o `expire_due` fecha). O trait é síncrono, então o store tem uma conexão numa thread própria e cada chamada bloqueia por uma ida e volta: chame de dentro de `spawn_blocking` em código async. Uma chamada que não responde a tempo (10 s por padrão) vira `PendingError::Store`, que recusa, e o `update` é um só `UPDATE ... WHERE state = 'pending'`, então um pedido decidido por outro processo nunca é decidido duas vezes.
- **Migrations.** `migrate`/`migrate_with` embutem o SQL, registram cada versão em `<prefix>_migrations` e rodam numa transação sob um lock consultivo. São aditivas (`CREATE ... IF NOT EXISTS`); nada apaga nem reescreve dado. Schema e nomes de tabela são validados como identificadores simples.

Os testes rodam contra um Postgres real quando `STRIG_PG_URL` está definida (veja Desenvolvimento) e pulam sem ela.

## Servidor de decisão e cliente remoto

O `strig-server` responde decisões por HTTP, para serviços que não embutem o motor.

```rust
let source = Arc::new(MemorySource::new(Snapshot::new(Arc::new(engine), grants)));
let router = DecisionServer::new(source).router();
let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
axum::serve(listener, router).await?;
```

O router atende `POST /v1/check`, `/v1/check/batch`, `/v1/list`, `/v1/who` e `/v1/access`, mais `GET /health/live` e `/health/ready`. Os grants vêm de uma `DecisionSource`; `MemorySource` guarda um `Snapshot` que você pode trocar com `replace`. As decisões usam o relógio do servidor. O contrato completo está em [`crates/strig-server/API.md`](crates/strig-server/API.md).

O cliente falha fechado. Só um `200` conta como resposta: timeout, conexão recusada, `503` ou corpo ilegível vira `ClientDecision::Denied` com o motivo, e um circuit breaker deixa de chamar um servidor que segue falhando.

```rust
let config = ClientConfig::default()
    .with_timeout(Duration::from_millis(250))
    .with_breaker(BreakerConfig::default().with_failure_threshold(5).with_open_for(Duration::from_secs(10)));
let client = Client::http("http://127.0.0.1:8080", config);

let request = CheckRequest::new(Subject::user("alice"), "document.view", Resource::new("document", "d1"));
if client.check(&request).await.is_allowed() {
    // serve o documento
}
```

### AuthZEN

`DecisionServer::new(source).with_authzen(AuthzenConfig::default())` serve também a [Authorization API 1.0 da OpenID AuthZEN](https://openid.net/specs/authorization-api-1_0.html) (Final, janeiro de 2026) ao lado do `/v1`, para que gateways e plataformas que falam o padrão consultem o Strig sem adaptador: `POST /access/v1/evaluation`, `/access/v1/evaluations` (com os três `evaluations_semantic`), `/access/v1/search/subject`, `/access/v1/search/action`, `/access/v1/search/resource` (com um `ResourceCatalog`) e `GET /.well-known/authzen-configuration` (com um issuer). As `subject.properties` viram atributos, com as propriedades `roles` e `principals` para papéis e principals; os passos mais amplos do caminho do recurso vêm de uma propriedade `path` ou de um `PathResolver` do servidor; `context` é o `env`. Falha fechado como o `/v1`: pedido malformado é `400`, permissão fora do catálogo é `{"decision": false}` e servidor que não consegue decidir responde `500`. O mapeamento e o que ficou de fora estão em [`crates/strig-server/API.md`](crates/strig-server/API.md#authzen-authorization-api).

```rust
let config = AuthzenConfig::default()
    .with_issuer("https://pdp.example.com")?
    .with_path_resolver(Arc::new(MyOrgTree));
let router = DecisionServer::new(source).with_authzen(config).router();
```

### Envoy

Com a feature `envoy` (desligada por padrão, sem `tonic` nem `prost` sem ela), `DecisionServer::envoy_service(EnvoyConfig)` serve a External Authorization do Envoy (`envoy.service.auth.v3.Authorization/Check`, gRPC) sobre a mesma fonte das rotas HTTP, para que uma malha de serviço ou um gateway feito em Envoy consulte o Strig antes de repassar o pedido. Um `EnvoyConfig` declarativo mapeia o pedido: o sujeito vem de um header ou do metadata do filtro (por exemplo as claims que o `jwt_authn` validou), cada método e padrão de path pede uma permissão, e o recurso é um template sobre os parâmetros do path. `OK` no allow; `PERMISSION_DENIED` com HTTP 403 no deny, num path que nenhuma regra cobre, sem sujeito, com a fonte fora ou com o prazo vencido, com um `x-strig-reason` fixo opcional. Path com segmentos de ponto ou separadores codificados não casa com nada. Veja [`crates/strig-server/API.md`](crates/strig-server/API.md#envoy-external-authorization-grpc-feature-envoy) e [`examples/envoy.yaml`](crates/strig-server/examples/envoy.yaml).

```rust
let envoy = EnvoyConfig::default()
    .with_subject_header("x-user")?
    .with_route("GET", "/healthz", RouteRule::public())?
    .with_route(
        "GET,HEAD",
        "/documents/{id}",
        RouteRule::require("document.view", ResourceTemplate::new("document", "{id}")),
    )?;
let service = DecisionServer::new(source).envoy_service(envoy);
service.serve(TcpListener::bind("127.0.0.1:9191").await?, shutdown).await?;
```

## Observabilidade

Todo crate tem uma feature `tracing` opcional, desligada por padrão. Ela traz spans pelo [`tracing`](https://docs.rs/tracing) e métricas pela fachada [`metrics`](https://docs.rs/metrics), então o backend é escolha sua: Prometheus, OpenTelemetry ou um recorder próprio. As features se encadeiam (`strig-sync/tracing` liga `strig/tracing`, `strig-postgres/tracing` e `strig-redis/tracing` ligam `strig-sync/tracing`, `strig-server/tracing` liga `strig/tracing`).

```toml
strig = { version = "0.8", features = ["tracing"] }
strig-server = { version = "0.8", features = ["tracing"] }
```

Com a feature desligada nada é compilado: os pontos instrumentados são a chamada direta. Ligada e sem subscriber nem recorder instalado, uma decisão custa cerca de 110 ns a mais (`decide/simple`: 518 ns desligada, 630 ns ligada, contra 517 ns antes de a feature existir; as operações maiores ficam dentro do ruído). O núcleo continua sem IO e continua compilando para WebAssembly com e sem a feature; lá o histograma de latência de decisão não é gravado, porque `std::time::Instant` não existe em `wasm32-unknown-unknown`. O binding JavaScript ainda não é instrumentado.

**Sem dado pessoal.** Um label de métrica é um destes: operação, permissão (só uma que o catálogo conhece; qualquer outra vira `unknown`), efeito, tipo de motivo, nome da invariante, etapa, resultado, status, tipo de mudança, nome do transporte, rota, código de erro, fase do breaker. Nunca id de sujeito, id de recurso, atributo nem corpo de requisição, e os spans levam os mesmos campos. Testes em cada crate rodam um cenário com ids reconhecíveis e falham se algum aparecer num label ou num span. Uma invariante sua rotula a métrica com o nome que você deu, então mantenha-o constante.

Uma decisão que uma invariante ou um override seu toma enquanto a governança julga uma mudança pertence a essa mudança: só a operação mais externa em cada thread alimenta as métricas, então `strig_decisions_total` conta o que a aplicação pediu. Os spans se aninham de qualquer jeito.

| Métrica | Tipo | Labels |
|---|---|---|
| `strig_decisions_total` | contador | `operation` (`decide`, `explain`), `effect`, `reason`, `permission` |
| `strig_decision_duration_seconds` | histograma | `operation` |
| `strig_query_duration_seconds` | histograma | `operation` (`list`, `who_can`, `who_can_on`) |
| `strig_mutations_total` | contador | `outcome` (`applied`, `refused`) |
| `strig_mutation_violations_total` | contador | `invariant` |
| `strig_approvals_total` | contador | `step` (`propose`, `approve`, `reject`, `expire`), `outcome` |
| `strig_audit_writes_total` | contador | `status` (`written`, `pending`, `dropped`, `refused`) |
| `strig_audit_pending` | gauge | nenhum (tamanho da fila de retentativa) |
| `strig_audit_write_failures_total` | contador | nenhum |
| `strig_audit_dropped_total` | contador | nenhum |
| `strig_sync_changes_total` | contador | `kind`, `direction` (`published`, `received`) |
| `strig_sync_publish_errors_total` | contador | `transport` |
| `strig_sync_sessions_open` / `strig_sync_sessions_opened_total` | gauge / contador | nenhum |
| `strig_sync_resyncs_total` | contador | `reason` (`reconnect`, `lagged`, `notice`) |
| `strig_sync_transport_reconnects_total` | contador | `transport` |
| `strig_sync_transport_failures_total` | contador | `transport`, `stage` (`subscribe`, `stream`) |
| `strig_server_requests_total` | contador | `route`, `status` |
| `strig_server_request_duration_seconds` | histograma | `route` |
| `strig_server_errors_total` | contador | `code` |
| `strig_client_calls_total` | contador | `route`, `outcome` |
| `strig_client_call_duration_seconds` | histograma | `route` |
| `strig_client_breaker_transitions_total` | contador | `to` (`closed`, `half_open`, `open`) |
| `strig_client_breaker_state` | gauge | nenhum (`0` fechado, `1` meio aberto, `2` aberto) |

| Span | Onde | Campos |
|---|---|---|
| `strig.decision` | `decide`, `check`, `explain` | `operation`, `permission`, `effect`, `reason` |
| `strig.query` | `list`, `who_can`, `who_can_on` | `operation`, `permission`, `kind` |
| `strig.governance.apply` | `Governance::apply` e `GovernanceAt` | `outcome` |
| `strig.approval` | `propose`, `approve`, `reject`, `expire_due` | `step`, `outcome` |
| `strig.audit.write` | cada registro de auditoria enviado ao sink | `mode` |
| `strig.sync.publish`, `strig.sync.relay`, `strig.sync.session` | publicação no hub, relay do transporte, uma sessão de cliente | `transport` na publicação |
| `strig.postgres.publish`, `strig.postgres.subscribe`, `strig.postgres.store.load`, `strig.postgres.store.reload`, `strig.postgres.store.commit_mutation`, `strig.redis.publish`, `strig.redis.subscribe` | os transportes | nenhum |
| `strig.server.request`, `strig.client.call` | o servidor de decisão e o cliente | `route`, `status` ou `outcome` |

Eventos (registro de auditoria descartado, conexão `LISTEN` perdida, breaker mudando de fase) saem em `warn` ou `info`. Os spans de decisão e de consulta são `debug`, os demais `info`.

[`crates/strig-server/examples/otlp.rs`](crates/strig-server/examples/otlp.rs) exporta os dois por OTLP/HTTP com `tracing-opentelemetry` e `metrics-exporter-opentelemetry`:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 cargo run -p strig-server --features tracing --example otlp
```

## JavaScript: Node, Bun e navegador

```sh
npm install @the-hades-organization/strig
```

```js
import { load } from '@the-hades-organization/strig';
const { Engine, Context } = await load(); // nativo no Node/Bun, wasm no navegador

const engine = new Engine(spec); // o mesmo JSON de EngineSpec do Rust
const ctx = new Context({ grants });
engine.check(ctx, { subject, permission: 'document.view', resource });
engine.apply({ actor, current, mutation: { add: grant }, invariants, audit: { level: 'standard' } });
```

No Node e no Bun, `load()` tenta o módulo nativo e recorre ao wasm. Defina `STRIG_BACKEND=native` ou `STRIG_BACKEND=wasm` para forçar um deles.

O módulo nativo sai em um pacote pequeno por plataforma, instalado pelo npm como dependência opcional de `@the-hades-organization/strig` (uma instalação típica baixa cerca de 2 MB e ocupa 8 MB em disco):

| Plataforma | Pacote |
| --- | --- |
| Linux x64 e arm64 (glibc) | `strig-linux-x64-gnu`, `strig-linux-arm64-gnu` |
| macOS Intel e Apple silicon | `strig-darwin-x64`, `strig-darwin-arm64` |
| Windows x64 | `strig-win32-x64-msvc` |

Qualquer outra plataforma (Alpine/musl, por exemplo) roda no backend wasm, que vem no pacote principal. Se você instalar com `--omit=optional` (ou `--no-optional`), `load()` também recorre ao wasm, e `STRIG_BACKEND=native` lança um erro com o nome do pacote a instalar.

A spec JSON cobre os overrides prontos, `resource_owner` e `permission_holder`. Funções de condição próprias (`call`), overrides próprios e invariantes próprias não fazem parte da spec: em JS são callbacks síncronos passados ao construtor de `Engine` (veja "Regras escritas em JavaScript").

### No navegador

`PermissionClient` (`/client`) conecta por SSE ou WebSocket, guarda as capacidades de cada escopo e decide localmente com o mesmo motor. Use para moldar a interface; o servidor continua decidindo em toda operação.

```js
import { PermissionClient } from '@the-hades-organization/strig/client';
const client = new PermissionClient({ url: '/permissions/events', scopes, strig, engine }).connect();
client.on('capabilities', () => render());
client.can('document.edit', resource);
```

### Custo de uma chamada e lotes

O `Context` guarda grants, tuplas, `env` e instante no lado Rust, então uma decisão nunca os reenvia; altere-os com `addGrant` (o mesmo `id` substitui), `removeGrant`, `addTuple`, `removeTuple`, `setNow` e `setEnv`. O que ainda cruza a fronteira a cada chamada é o pedido, e o binding o envia como uma string de `JSON.stringify` (a decisão volta do mesmo jeito) quando ele é JSON simples; um pedido com `undefined`, `NaN`, funções, bigints ou instâncias de classe segue o caminho original e seus erros. `check` responde um booleano sem montar o `Decision`.

Para decidir vários pedidos contra um `Context` e um instante, cruze a fronteira uma vez só:

```js
const allowed = engine.checkMany(ctx, requests);   // boolean[], na ordem
const traces = engine.explainMany(ctx, requests);  // Explanation[], na ordem
```

Um pedido ilegível lança erro e não decide nenhum; nunca vira um `false` silencioso. Os números por caso estão em [`docs/benchmarks.md`](docs/benchmarks.md).

### Regras escritas em JavaScript

A função da condição `call`, o override próprio e o `Invariant` próprio existem também em JS, como callbacks síncronos passados ao construtor de `Engine`. O motor os chama no meio da decisão ou do `apply`, e eles aparecem como os nativos: o rastro de `explain` nomeia o override, a recusa carrega a sua violação e a auditoria registra como registra as invariantes embutidas.

```js
const engine = new Engine(spec, {
  // condições `call`: { op: 'call', func: 'same_dept', args: [{ attr: 'subject.dept' }, { attr: 'resource.dept' }] }
  conditions: { same_dept: ([a, b]) => a === b },
  // Decide antes dos grants: 'allowed', 'denied' ou 'abstained' (nada). `except` pula permissões.
  overrides: [{ name: 'frozen', except: ['project.view'], evaluate: ({ permission }) => (frozen ? 'denied' : undefined) }],
  invariants: {
    // O papel de um ambiente nunca excede o global.
    env_role_within_global({ mutation }) {
      if (!('assign_role' in mutation)) return;
      const { subject, role } = mutation.assign_role;
      if (role.scope?.kind !== 'environment' || rank(role.role) <= globalRank(subject)) return;
      return { message: `${role.role} no ambiente excede o papel global`, suggestion: downgrade(subject, role) };
    },
    // Um papel em uso não se apaga.
    role_in_use({ mutation, before }) {
      if (!('remove' in mutation)) return;
      const grant = before.find((g) => g.id === mutation.remove.id);
      if (grant?.subject.kind === 'role' && inUse(grant.subject.id)) return `o papel ${grant.subject.id} está em uso`;
    },
  },
});

engine.apply({ actor, current, mutation, invariants: [{ kind: 'custom', name: 'env_role_within_global' }, { kind: 'custom', name: 'role_in_use' }] });
```

- A função de condição recebe os operandos já resolvidos e devolve um boolean. A invariante recebe `{ actor, mutation, before, after, now }` (a `mutation` tem a forma que o `apply` aceita) e devolve nada para aceitar, ou um texto, ou `{ message, suggestion? }` para recusar. A `suggestion` é uma mudança; a governança a confere contra todas as invariantes antes de ela aparecer.
- **Um throw nega, nunca derruba.** Condição que lança (ou não devolve boolean) é erro de condição: o grant de allow não vale, o de deny ainda vale, e o rastro traz a mensagem. Override que lança responde `denied`. Invariante que lança recusa com a mensagem do erro.
- **Os callbacks são síncronos.** Uma promise não é aguardada; é resposta errada e nega como um throw.
- **Sem reentrada.** Callback que chama o motor, ou muda outro `Context`, recebe `REENTRANT_CALL`; mudar o `Context` em decisão é recusado pelo runtime. Leia o que precisa antes da chamada e guarde na closure.
- Override próprio é opaco para listagens (`list`), como todo override que não descreve o seu alcance: os recursos que ele pode decidir ficam como resíduo, nunca como permitidos.

### Tempo real num backend JS

`/server` traz `Hub`, `openSession`, `sseResponse` (Fetch API: Bun.serve, Hono, Deno), `pipeSse` (`http` do Node) e três transportes: `redisTransport` (node-redis e o `RedisClient` do Bun), `ioredisTransport` e `pgTransport` (pacote `pg`). Os avisos usam o formato do `strig-sync`, então instâncias Rust e JS podem dividir o mesmo canal.

### Grants e papéis em arquivo JSON

Para um sistema sem Postgres nem Redis, `/store` guarda os grants e as atribuições de papel num arquivo JSON (Node e Bun):

```ts
import { openJsonStore } from '@the-hades-organization/strig/store';

const store = await openJsonStore({ path: './strig.json', createIfMissing: true });
const provider = engineProvider({ engine, Context, loadGrants: store.loadGrants }); // a fonte de grants
const subject = store.subject({ kind: 'user', id: 'ana' });                          // + os papéis do arquivo

const result = await store.apply(engine, { actor, mutation: { assign_role: { subject, role: { role: 'admin' } } }, invariants });
// aceita: os novos grants e papéis são gravados; recusada: nada é gravado
```

- **Arquivo:** `{ "version": 1, "grants": [...], "roles": { "<id do sujeito>": [<atribuição>, ...] } }`. Os papéis em si (a hierarquia) ficam na spec do motor; o arquivo guarda quem tem qual.
- **Falha fechado.** Arquivo ausente, JSON inválido, id de grant repetido ou `version` diferente de 1 lança `JsonStoreError` (`STORE_NOT_FOUND`, `STORE_CORRUPT`, `STORE_VERSION`) na carga. O store nunca começa vazio sozinho; `createIfMissing` é o jeito explícito de começar um.
- **Escrita atômica e serializada.** Arquivo temporário no mesmo diretório, `fsync`, `rename` e `fsync` do diretório. Chamadas no mesmo processo entram numa fila; entre processos vale um `<arquivo>.lock` (criado com `O_EXCL`), e o lock cujo dono morreu neste host, ou mais velho que `lockStaleMs` (30 s), é tomado. Cada mudança relê o arquivo sob o lock, então processos não se sobrescrevem. `STORE_LOCK_TIMEOUT` depois de `lockTimeoutMs` (5 s).
- **Mudanças:** `addGrant`, `updateGrant`, `removeGrant`, `assignRole`, `revokeRole`, `setRoles`, ou `apply(engine, input)`, que roda a governança sobre os grants que o arquivo tem agora e grava o que ela aceita.
- **Recarga:** `reload()` depois de uma edição de fora, ou `watch()` para recarregar sozinho (observa o diretório, porque o rename troca o arquivo). Arquivo ruim na recarga mantém o último snapshot bom, lança em `reload()` e vai para `onError` no `watch()`. `onChange` dispara a cada recarga e gravação.
- Fora daqui: registros de auditoria e uma versão só em Rust.

### Express, Fastify e NestJS

As três integrações recebem as mesmas opções e decidem em cada rota:

```js
import { load, scopeFromString } from '@the-hades-organization/strig';
import { authorize } from '@the-hades-organization/strig/express';

const { Engine, Context } = await load();
const options = {
  subject: (req) => (req.headers['x-user'] ? { kind: 'user', id: req.headers['x-user'] } : undefined),
  resource: (req) => scopeFromString(`document:${req.params.id}/org:o1`),
  local: { engine: new Engine(spec), context: new Context({ grants }), now: () => Date.now() },
};

app.get('/doc/:id', authorize({ ...options, permission: 'document.view' }), handler);
```

| Opção | Significado |
|---|---|
| `subject(req)` | O sujeito; não devolver nada responde `401`. |
| `resource(req)` | O recurso. |
| `local: { engine, context, now }` ou `remote: RemoteClient` | De onde vem a decisão. Passe exatamente um. |

A requisição só passa quando a decisão permite:

| Resultado | Status | Mude com |
|---|---|---|
| Sem sujeito | `401` | `unauthenticatedStatus` |
| Negado | `403` | `denyStatus` |
| Não foi possível decidir | `503` | `failureStatus` |
| Sua função `subject` ou `resource` lançou exceção | `500`, sem detalhe | `errorStatus`, `onError` |

- **Fastify** (`/fastify`): o mesmo `authorize`, mais um `plugin` que acrescenta `fastify.strigCan`.
- **NestJS** (`/nestjs`): `@Can('document.view')` num handler ou controller, com `new StrigGuard(options)` como guard.

#### Uma tabela de rotas, nega por padrão

Para manter todas as regras num só lugar, dê à integração uma tabela em vez de uma permissão por handler. Uma requisição que nenhuma regra cobre é recusada (`denyStatus`, 403); uma rota só é pública quando a regra diz `public: true`.

```js
import { authorizeRoutes } from '@the-hades-organization/strig/express';

const routes = [
  { method: 'GET', path: '/health', public: true },
  { method: 'GET', path: '/doc/:id', permission: 'document.view', resource: (req, params) => docScope(params.id) },
  { method: ['PUT', 'DELETE'], path: '/doc/:id', permission: 'document.edit', resource: (req, params) => docScope(params.id) },
];
app.use(authorizeRoutes({ subject, local: { engine, context }, routes })); // antes dos routers
```

Os caminhos usam a sintaxe do framework: segmentos literais, `:nome` para um segmento e um `*` final para um ou mais. A primeira regra que casa decide, então escreva as específicas primeiro; `HEAD` cai nas regras de `GET` e `*` como método vale para qualquer um. A tabela casa do jeito que o framework roteia, para que nenhuma requisição escape de uma regra protegida para uma pública mais ampla: cada segmento é decodificado (percent-decoding) antes da comparação (`/%61dmin/1` é `/admin/1`; `%2F` fica dentro do segmento; escape malformado não casa com nada), e os literais ignoram maiúsculas com `caseSensitive: false`. O padrão é o do próprio framework: o Express ignora maiúsculas, o Fastify diferencia (defina `caseSensitive` na tabela se mudou a opção do Fastify) e o Nest segue a plataforma. Passe `{ caseSensitive: false }` a `assertRoutesCovered` num app Express. Cada regra tem `permission` ou `public: true` (tabela inválida lança na subida). `resource` recebe a requisição e os `params` casados: no nível do app o Express ainda não preencheu `req.params`.

- **Express** (`/express`) e **Fastify** (`/fastify`): `authorizeRoutes(options)` é um middleware global ou hook `onRequest` (`fastify.addHook('onRequest', ...)`). Também responde 403 para URLs sem rota, e o preflight de CORS precisa de uma regra ou de ser respondido antes dele.
- **NestJS** (`/nestjs`): `{ provide: APP_GUARD, useValue: new StrigRouteGuard(options) }`. A tabela decide primeiro. Se ela libera, um `@Can` no handler soma uma segunda checagem que também precisa passar: `@Can` restringe, nunca libera o que a tabela nega (e vale também numa regra `public`). Handler sem `@Can` não precisa de mais nada.

Coloque a tabela sob teste para que ela não se afaste do app (`/testing`):

```js
import { expressRoutes, assertRoutesCovered } from '@the-hades-organization/strig/testing';

assertRoutesCovered(expressRoutes(app), routes); // lança listando rotas sem regra e regras sem rota
```

`expressRoutes(app)` lê um app ou router do Express 4 ou 5 (routers aninhados incluídos, sub-apps montados não); `nestRoutes(app)` faz o mesmo para um app Nest no adaptador Express depois de `app.init()`; no Fastify chame `collectFastifyRoutes(fastify)` antes de registrar as rotas e use o array devolvido com o app pronto. `auditRoutes(routes, tabela)` devolve `{ uncovered, unusedRules, ok }` se preferir asserir por conta própria.

Express, Fastify e NestJS são peer dependencies opcionais. Uma integração que você não importa não custa nada, e importar uma cujo peer falta lança `MissingPeerError`.

Para obter as decisões de um [servidor de decisão](#servidor-de-decisão-e-cliente-remoto), passe um `RemoteClient` (`/remote`) como `remote`. Ele tem timeout e breaker, e nega quando não há resposta:

```js
import { RemoteClient } from '@the-hades-organization/strig/remote';
const remote = new RemoteClient({ url: 'http://127.0.0.1:8080', timeoutMs: 250 });
const { allowed } = await remote.check({ subject, permission: 'document.view', resource });
```

### Tipos do catálogo para o frontend

Uma permissão pode levar o nome exibido e a descrição por locale (`labels` / `descriptions`, ao lado de `label` / `description`; em Rust `PermissionDef::localized_label("pt-BR", "Editar")`). São opcionais e não se declaram na linguagem de políticas, só no export do catálogo (JSON) ou no builder. O `strig-types` transforma um catálogo exportado num único `.ts` com a união `PermissionId`, a constante `PERMISSIONS` com os metadados e os helpers `isPermissionId`, `permissionLabel` e `permissionDescription` (locale com volta ao texto padrão). A saída é ordenada, então só muda quando o catálogo muda.

```sh
npx strig-types catalog.json -o src/permissions.generated.ts
```

```ts
import { generateTypes } from '@the-hades-organization/strig/types'; // o mesmo, como função
import { PermissionClient } from '@the-hades-organization/strig/client';
import type { PermissionId } from './permissions.generated';

const engine = new strig.Engine<PermissionId>(spec); // estrito: check, explain, list, whoCan... só aceitam os ids; sem o parâmetro, qualquer string
const client = new PermissionClient<PermissionId>(/* ... */);
client.can('users:read', resource); // só ids da união compilam; estreite uma string com isPermissionId antes
```

### React e Angular

`/react` e `/angular` põem o [`PermissionClient`](#tempo-real) de tempo real (`/client`) atrás das primitivas de interface de sempre. A decisão é local, sobre as capacidades que o stream entrega, e a resposta é **negar** sempre que não há nenhuma: antes das primeiras capacidades, depois de uma desconexão, durante um resync, no servidor (SSR) e para um escopo que os grants não cobrem. React 18 e 19, Angular 17+ (standalone, signals). Os dois aceitam o `PermissionId` gerado pelo `strig-types` como parâmetro de tipo.

```tsx
import { PermissionClient } from '@the-hades-organization/strig/client';
import { StrigProvider, useCan, Can, useStrigStatus } from '@the-hades-organization/strig/react';
import type { PermissionId } from './permissions.generated';

const client = new PermissionClient<PermissionId>({ url: '/strig/stream', scopes: [project], strig, engine });

<StrigProvider client={client}>
  <Can<PermissionId> permission="document.edit" resource={doc} fallback={<SoLeitura />}>
    <Editor />
  </Can>
</StrigProvider>;

const canEdit = useCan<PermissionId>('document.edit', doc); // re-renderiza quando chegam capacidades
const { connected, resyncing, error } = useStrigStatus();
```

O `StrigProvider` abre o stream ao montar e fecha ao desmontar (`connect={false}` deixa isso com você), e nunca conecta no servidor. Sem provider, todo hook nega.

```ts
// app.config.ts
import { provideStrig } from '@the-hades-organization/strig/angular';
providers: [provideStrig(client)]; // { connect: false } para abrir o stream você mesmo

// componente
import { StrigCanDirective, StrigService, strigCanActivate } from '@the-hades-organization/strig/angular';
// template: <button *strigCan="'document.edit'; resource: doc; else somenteLeitura">Editar</button>
canEdit = inject(StrigService<PermissionId>).can('document.edit', this.doc); // Signal<boolean>; os argumentos podem ser signals

// rotas
{ path: 'doc/:id', canActivate: [strigCanActivate<PermissionId>('document.view', (route) => resourceOf(route))] }
```

O guard de rota espera as primeiras capacidades (`waitMs`, padrão 5000 ms) para que um link direto não seja recusado enquanto o stream abre, e então decide localmente; timeout ou negação devolvem `false`, ou o que `onDeny` devolver (roda no contexto de injeção, então pode devolver uma `UrlTree`).

React e Angular são peer dependencies opcionais e entram por import estático, para que o seu bundler resolva a própria cópia (uma cópia carregada por fora poderia ser um segundo React e quebrar os hooks). Por isso, um peer ausente falha na resolução do módulo, com o erro do próprio loader citando o pacote, e não com `MissingPeerError` como nas integrações Express, Fastify e NestJS. O pacote entrega o Angular como saída Ivy parcial, para o linker do Angular. Vue e Svelte podem seguir o mesmo caminho: a ponte em `client-bridge.ts` é neutra de framework e cada binding tem cerca de cem linhas.

### Filtrando uma listagem no Prisma, Drizzle e Kysely

`engine.list(...)` diz o que um sujeito alcança num kind; `/prisma`, `/drizzle` e `/kysely` transformam essa resposta no `where` do seu ORM, com o mesmo significado que o `PgTables` tem em Rust. Cada um recebe o resultado do `list` e um mapa de onde o recurso guarda o que o filtro lê, e devolve `{ permission, where, settled?, residual }`. Drizzle e Kysely são peers opcionais (o Kysely nunca é importado: o builder chega como argumento do callback); o Prisma não precisa de nenhum, pois o `where` é um objeto simples.

```ts
import { toWhere } from '@the-hades-organization/strig/prisma';

const result = engine.list(ctx, subject, 'document.view', 'document', { layout: ['document', 'project', 'org'] });
const { where, settled, residual } = toWhere(result, {
  kind: 'document',
  id: 'id',
  paths: { project: 'projectId', org: 'project.orgId' }, // caminho com ponto atravessa uma relação to-one
  attrs: { owner: 'ownerId' },
  optionalRelations: ['project'], // só no Prisma: relações que podem faltar
});
const documents = await prisma.document.findMany({ where });
```

```ts
import { toWhere } from '@the-hades-organization/strig/drizzle'; // paths: { project: documents.projectId, ... }
const { where } = toWhere(result, { kind: 'document', id: documents.id, paths: { project: documents.projectId, org: documents.orgId } });
const rows = await db.select().from(documents).where(where);

import { toWhere as toKyselyWhere } from '@the-hades-organization/strig/kysely'; // colunas como texto
const { where: kyselyWhere } = toKyselyWhere(result, { kind: 'document', id: 'id', paths: { project: 'project_id', org: 'org_id' } });
const rows2 = await db.selectFrom('document').selectAll().where(kyselyWhere).execute();
```

- **Falha fechada.** Um kind ou atributo que o filtro lê e o mapa não tem, um nó da expressão sem forma de consulta, um filtro de outro kind que o do mapa: tudo lança `OrmFilterError` (`code`: `UNMAPPED_KIND`, `UNMAPPED_ATTRIBUTE`, `UNSUPPORTED_EXPR`, `UNSUPPORTED_VALUE`, `KIND_MISMATCH`). Nada vira "todas as linhas"; o que é certamente vazio vira uma condição impossível.
- **Um deny alcança só o que nomeia.** Todo teste é verdadeiro ou falso, nunca `NULL`, então `NOT (project_id = 'p2')` mantém as linhas sem projeto, como o `engine.check` faz. No Prisma a negação desce até os campos (`{ OR: [{ projectId: null }, { projectId: { not: 'p2' } }] }`), e uma relação que pode faltar entra em `optionalRelations`; esquecer uma só custa linhas que um deny derrubaria, nunca abre acesso.
- **Resíduo não é permissão.** Uma condição sobre o recurso, um override ou uma estratégia que o banco não resolve fica em `residual`. `where` é o limite superior (toda linha que pode estar permitida) e `settled` o inferior (linhas permitidas seja qual for o resíduo), presente só com resíduo: confira com `engine.check` as linhas de `where` fora de `settled`. Sem resíduo, `where` é exato.
- **Um contrato.** Cada módulo também exporta um objeto (`prisma`, `drizzle`, `kysely`) com `toWhere(filter, mapping)`, tipado sobre o `PermissionId` do `strig-types`.

Os testes de unidade conferem o objeto que cada adapter monta, e um oráculo roda cada cenário (allow por kind, por âncora, por id exato, denies que recortam, uma condição que fica como resíduo) contra o SQLite (Drizzle e Kysely) e um avaliador da forma do Prisma, comparando as linhas com os ids que o `engine.list` resolve. TypeORM, Sequelize e MikroORM ainda não têm adapter; o mapa e o compilador (`bounds`, `Emitter`) são o que um novo reaproveitaria.

## Python

`strig-auth` é o binding Python sobre o mesmo motor e o mesmo JSON `EngineSpec` das APIs Rust e JavaScript: uma extensão nativa (PyO3), com um wheel `abi3` por plataforma para Python 3.9 em diante e type stubs (`py.typed`).

```sh
pip install strig-auth
```

```python
import strig
from strig import dsl

spec = dsl.load_project_dir("policies")          # ou um dict: o JSON do EngineSpec
engine = strig.Engine(spec)

ctx = strig.Context(grants, tuples=[...], env={"dept": "eng"}, now=1_700_000_000_000)
ctx.add_grant(grant); ctx.remove_grant("g1"); ctx.set_now(None)

request = {"subject": {"kind": "user", "id": "ana"}, "permission": "project.edit",
           "resource": strig.scope_from_string("project:p1/org:o1")}
engine.check(ctx, request)                        # bool
engine.decide(ctx, request)                       # {"effect": "allow", "matched": [...], "reason": {...}}
engine.explain(ctx, request)                      # o rastro
engine.check_many(ctx, [request, other], now=1_700_000_000_000)
engine.list(ctx, subject, "project.view", "project")
engine.who_can(ctx, "project.view")

result = engine.apply({"actor": actor, "current": grants, "mutation": {"add": grant},
                       "invariants": [{"kind": "custom", "name": "role_in_use"}],
                       "audit": {"level": "forensic", "failMode": "open"}})
```

- **Mesmo JSON, mesmos nomes.** Argumentos e resultados são os dicts e listas que a API JavaScript recebe e devolve, com os mesmos campos em camelCase (`validFrom`, `grantId`, `auditStatus`); métodos e argumentos nomeados são snake_case (`check_many`, `who_can_on`, `audit_sink`). O que não é JSON (`nan`, um `set`, chave que não é texto, int acima de 64 bits) é recusado com `INVALID_ARGUMENT`; nada é convertido à força.
- **Erro é exceção com `code`.** Uma chamada que falha levanta `strig.StrigError` com `.code` igual ao `errorCode` do binding JavaScript (`INVALID_INPUT`, `INVALID_ARGUMENT`, `UNKNOWN_SUBJECT`, `REENTRANT_CALL`, ...); compare o código, não a mensagem. A linguagem de políticas levanta `strig.DslError` (um `StrigError`) com `.diagnostics`.
- **Regras escritas em Python.** `Engine(spec, conditions={...}, overrides=[{"name": ..., "except": [...], "evaluate": fn}], invariants={...}, audit_sink=fn, audit_redact=fn, on_audit_drop=fn, audit_policy={...})` recebem callables síncronos com o mesmo contrato dos hooks JavaScript: uma exceção nega (condição que levanta não concede, override que levanta responde `denied`, invariante que levanta recusa com a mensagem), uma corrotina é resposta errada, e um callback que chama o motor ou muda um `Context` recebe `REENTRANT_CALL`. A GIL fica presa durante a chamada, então o callback roda na thread que está decidindo.
- **O tempo é explícito.** Todo método que decide aceita um `now` (ms UTC) que vale mais que `ctx.set_now`; sem nenhum, o motor falha fechado nas janelas de validade. O relógio do sistema só é usado por `apply`/`propose` no registro de auditoria e por `Exclusive` quando falta `now`.
- `strig.Exclusive(...)`, `strig.verify_audit_chain(records, anchors)` e `strig.audit_estimate(level, records)` espelham os do JavaScript. `strig.dsl` tem `compile`, `print`, `convert`, `format`, `is_formatted`, `load_project` e `load_project_dir`.

Para compilar a partir do repositório: `pip install maturin && cd crates/strig-python && maturin develop && pytest`.

## Go

`github.com/The-Hades-Organization/Strig/bindings/go` é o binding de Go sobre o mesmo motor e o mesmo `EngineSpec` JSON das outras APIs. Roda o motor compilado para WebAssembly (`crates/strig-wasi`, uma ABI C simples com JSON na entrada e na saída) no [wazero](https://wazero.io), Go puro e sem cgo, e o módulo vai embutido com `go:embed`. Go 1.22 ou superior.

```sh
go get github.com/The-Hades-Organization/Strig/bindings/go@<tag>   # uma tag de release deste repositório
```

```go
import strig "github.com/The-Hades-Organization/Strig/bindings/go"

engine, err := strig.NewEngine(spec)               // spec: um map, uma struct ou um json.RawMessage
defer engine.Close()

ctx, _ := engine.NewContext(map[string]any{"grants": grants, "env": map[string]any{"dept": "eng"}})
ctx.AddGrant(grant); ctx.RemoveGrant("g1")

request := map[string]any{"subject": subject, "permission": "project.edit", "resource": resource}
allowed, err := engine.Check(ctx, request)         // (bool, error): um erro nunca é um allow
decision, err := engine.Decide(ctx, request)       // *Decision{Effect, Reason, Matched, Warnings}
explanation, err := engine.Explain(ctx, request, strig.WithNow(time.Now()))
many, err := engine.CheckMany(ctx, []any{request, other})
policy, err := strig.Compile(text)                 // a linguagem de políticas, sem motor
```

- **Mesmo JSON, mesmos códigos.** Pedidos e resultados são o JSON da API JavaScript, com os mesmos campos em camelCase. Uma falha é um `*strig.Error` cujo `Code` é o `errorCode` do binding JavaScript (`INVALID_INPUT`, `UNKNOWN_SUBJECT`, `DSL_PARSE`, ...), com `Diagnostics` na linguagem de políticas; use `strig.CodeOf(err)` ou `errors.As`.
- **Falha fechada.** `Check` devolve `false` com o erro, nunca `true`. Se o módulo der trap, a instância é descartada e toda chamada seguinte devolve `strig.ErrBroken`. Engine ou contexto fechado, ou contexto de outro engine, é erro.
- **Concorrência.** Um `Engine` é seguro para uso concorrente, mas uma instância WebAssembly tem uma thread só, então as chamadas são serializadas. Para throughput paralelo dê a cada worker o seu `engine.Fork()` (instância própria, mesma spec, sem estado compartilhado). Um `Context` pertence ao engine que o criou.
- **O tempo é explícito.** `WithNow(t)` ou `ctx.SetNow(t)` definem o instante; sem um, o motor falha fechado nas janelas de validade. `Apply`, `Propose`, `Resolve` e `Expire` usam o relógio do host quando a entrada não traz `now`.
- **Ainda fora deste binding:** callbacks (condição `call`, overrides, invariantes escritos em Go), o sink de auditoria e os recursos exclusivos. Uma spec que precisa de callback falha fechada.

O `.wasm` também é asset da release (`strig-<versão>.wasm`), para qualquer outro host que fale WebAssembly. Para refazer o módulo embutido: `sh bindings/scripts/build-wasi.sh`, depois `cd bindings/go && go test ./...`.

## Java e Kotlin

`io.github.the-hades-organization:strig` é o binding da JVM: o mesmo módulo WebAssembly, rodando no [Chicory](https://github.com/dylibso/chicory) (JVM pura, sem código nativo), com o mesmo `EngineSpec` JSON. Java 17 ou superior; o Kotlin usa as mesmas classes.

```xml
<dependency>
  <groupId>io.github.the-hades-organization</groupId>
  <artifactId>strig</artifactId>
  <version>${strig.version}</version>
</dependency>
```

```java
import io.github.thehadesorganization.strig.*;

try (Engine engine = new Engine(spec);                 // spec: um Map, um record ou um JsonNode
     Context ctx = engine.newContext(Map.of("grants", grants))) {
  ctx.addGrant(grant);
  boolean allowed = engine.check(ctx, request);        // uma exceção nunca é um allow
  Decision decision = engine.decide(ctx, request, Instant.now());
  Map<String, Object> explanation = engine.explain(ctx, request);
  List<Boolean> many = engine.checkMany(ctx, List.of(request, other));
} catch (StrigException e) {
  e.code();                                            // INVALID_INPUT, UNKNOWN_SUBJECT, DSL_PARSE, ...
}
Map<String, Object> policy = Strig.compile(text);      // a linguagem de políticas, sem motor
```

```kotlin
Engine(spec).use { engine ->
    engine.newContext(mapOf("grants" to grants)).use { ctx -> engine.check(ctx, request) }
}
```

- **Mesmo JSON, mesmos códigos.** `StrigException.code()` é o `errorCode` do binding JavaScript; `diagnostics()` traz as posições da linguagem de políticas.
- **Falha fechada.** `check` lança exceção em vez de devolver `true` quando não consegue decidir; uma instância que deu trap é descartada e toda chamada seguinte lança `INTERNAL`.
- **Concorrência.** Um `Engine` é seguro para uso concorrente, com chamadas serializadas; dê a cada worker um `engine.fork()` para throughput paralelo. Um `Context` pertence ao seu engine. Feche os dois.
- **O tempo é explícito.** Todo método que decide tem uma sobrecarga com `Instant`; sem um, o motor falha fechado nas janelas de validade.
- **Ainda fora deste binding:** callbacks (condição `call`, overrides, invariantes escritos em Java), o sink de auditoria e os recursos exclusivos.

A publicação no Maven Central ainda não está ligada (precisa da conta e da chave de assinatura do projeto). Até lá, gere o jar pelo repositório: `sh bindings/scripts/build-wasi.sh jvm && cd bindings/jvm && mvn verify`.

## Linguagem de políticas

Com a feature `dsl`, uma política pode ser escrita em texto em vez de JSON. A mesma política tem três sintaxes, Blocks, Rules e Actors, e `convert` passa de uma para outra. Todo erro traz posição e dica. O JSON validado continua sendo a fonte da verdade.

Experimente no [playground](https://strig-playground.vercel.app), que roda o motor de verdade compilado para WebAssembly. O [guia](docs/dsl.md) mostra as três sintaxes lado a lado e a gramática.

```rust
use strig::dsl::{self, Language};

const SOURCE: &str = "language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
";

let parsed = dsl::parse("policy.strig", SOURCE)?;
let json = parsed.policy.to_json()?;
let as_rules = dsl::convert(SOURCE, Language::Rules)?;
```

`as_rules` fica com:

```text
language rules

kinds org

permission org.read on org
```

As condições de `when` se escrevem igual nas três sintaxes, por exemplo `a starts_with b`, `env.ip ip_in "10.0.0.0/8"`, `time_between "09:00" "17:30"` e `weekday_in ["mon", "tue"]`. O validador recusa CIDR, horário, dia da semana ou fuso horário que não consegue ler. Quando um nome está a um erro de digitação de uma permissão, papel ou pai declarado, a dica acrescenta ``did you mean `x`?``.

- **Formatação.** `strig::dsl::format` e `is_formatted` reescrevem uma fonte no layout canônico da sintaxe dela e mantêm os comentários. `strig-inspect fmt [--check] <arquivo|dir>` faz o mesmo com arquivos `.strig`; `--check` lista os que mudariam e sai com 1.
- **Arquivos.** Com `dsl-fs`, `strig::dsl::fs::read_dir` lê todos os `*.strig` de um diretório num `Project`, e `write_file` grava uma política de volta.

### No Node

O binding expõe a mesma linguagem, nativo e WebAssembly, atrás de `load()`. Uma política compilada é o JSON canônico, o mesmo para as três sintaxes, com os comentários em `notes`.

```js
import { load } from '@the-hades-organization/strig';
const strig = await load();

const source = `language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
`;

const policy = strig.compile(source, { file: 'policy.strig' }); // JSON canônico
const rules = strig.print(policy, 'rules'); // 'blocks' | 'rules' | 'actors'
const actors = strig.convert(source, 'actors'); // texto para texto
const merged = strig.loadProject([
  { path: 'org.strig', text: source },
  { path: 'team.strig', text: strig.convert(source.replaceAll('org', 'team'), 'actors') },
]);
const fromDisk = strig.loadProjectDir?.('./policy'); // só no módulo nativo
```

- `format(source)` devolve a fonte no layout canônico da sintaxe dela; `isFormatted(source)` diz se ela já está assim.
- `loadProjectDir(dir)` só existe no módulo nativo, porque o WebAssembly não acessa arquivos. Ele lê os `*.strig` do diretório e recusa um arquivo de política que seja link simbólico. Passe só um `dir` de origem confiável.

Toda falha é um `Error` cujo `code` é o mesmo nos dois alvos:

| `code` | Causa |
|---|---|
| `DSL_PARSE` | O texto tem erro de sintaxe. |
| `DSL_VALIDATE` | A sintaxe está certa, mas a política é inválida. |
| `DSL_CONFLICT` | Duas fontes declaram a mesma coisa; as duas posições vêm no erro. |
| `DSL_UNREPRESENTABLE` | A sintaxe de destino não consegue expressar a política. |
| `DSL_UNSUPPORTED` | A sintaxe não existe neste build. |
| `DSL_LIMIT` | Um limite de tamanho ou de quantidade foi excedido. |
| `DSL_DUPLICATE_SOURCE` | O mesmo `path` aparece duas vezes em `loadProject`. |
| `DSL_IO` | Um arquivo ou link em `loadProjectDir`. A mensagem leva o caminho, então não a repasse a um cliente remoto. |

`error.diagnostics` lista até 100 entradas `{ file, line, column, message, hint, related? }`; quando houve mais, a última diz "and N more". `file`, `line` e `column` são `null` numa política que não veio de texto. `related` (`{ file, line, column }`) aparece num `DSL_CONFLICT`.

```js
try {
  strig.compile('language blocks\n\npermission {', { file: 'a.strig' });
} catch (error) {
  error.code; // 'DSL_PARSE'
  const [first] = error.diagnostics; // first.file === 'a.strig', first.line === 3
}
```

### Diff e lint de uma política

`strig diff <antes> <depois>` lista as decisões que mudam entre duas versões de uma política (diretórios ou arquivos
`.strig`): quem, qual permissão, sobre o quê, se o acesso `widened` (ampliou) ou `narrowed` (restringiu), e o grant ou
override responsável em cada lado. `strig lint <dir>` acha política que nunca age: grant sombreado, deny inalcançável,
permissão sem titular, papel sem uso, `implied_by` redundante, condição sempre falsa ou verdadeira, campo nunca concedido.

```sh
strig diff main/policies policies --fail-on allow     # exit 1 se algum acesso ampliou
strig lint policies/ --json                           # códigos L001..L009, severidade, posição, dica
```

```js
const found = strig.diff(before, after, { fixture: { resources: ['org:1'] } });
const findings = strig.lint(policy, { ignore: ['unused-role'] });
```

Sem fixture as perguntas saem dos catálogos e dos grants e são limitadas por `QueryLimits`; um diff cortado por limite
vem marcado `partial`, e não achar mudança então não prova que não há. Em Rust é `strig::dsl::analysis`. A action
`strig-test` aceita `diff-base` para comparar com a base da PR. Veja [o guia](docs/dsl.pt-BR.md#analisando-uma-política).

### Testando uma política

Os testes ficam ao lado da política: arquivos `*.strig-test.json` com casos `check` (sujeito, permissão, recurso, instante
e ambiente opcionais, `allow` ou `deny` esperado, e opcionalmente o motivo e o grant que decide) e casos `mutation` (um
ator e uma mudança, aceita ou recusada, e opcionalmente por qual invariante). `strig test` os roda, e erro no próprio teste
nunca é aprovação:

```sh
cargo install strig-cli --locked
strig test policies/ --junit test-results/strig.xml   # exit 1 em falha, 2 em entrada inválida
```

```yaml
- uses: The-Hades-Organization/Strig/.github/actions/strig-test@v0.9.0
  with: { path: policies, version: 0.9.0 }
```

O mesmo runner é `strig::dsl::testing` em Rust e `strig.runTests(policy, tests)` em JavaScript e `strig.dsl.run_tests(policy, tests)` em Python. O formato, o relatório e
os códigos de saída estão [no guia](docs/dsl.pt-BR.md#testando-uma-politica); `examples/policy-tests/` tem um projeto que passa.

### Editor

`strig-lsp` é um language server para arquivos `.strig`, e `editors/vscode` é a extensão do VS Code que o usa. Os dois leem o projeto como o `strig test` lê: todo `*.strig` do diretório do arquivo aberto é uma política só, em qualquer mistura das três sintaxes, e todo `*.strig-test.json` ao lado é um arquivo de testes. Buffers não salvos contam.

- **Diagnósticos enquanto você digita**, com a posição e a dica do validador, inclusive conflitos entre arquivos (o outro lado vai como local relacionado) e os erros de um `*.strig-test.json`.
- **Formatar documento**, com o mesmo layout de `strig::dsl::format`; fonte que não compila fica como está.
- **Completar** ids de permissão, kinds, papéis, sujeitos e operadores de condição a partir do projeto, filtrados pela linha (`depends_on = [`, `inherits `, `when = ...`).
- **Hover** numa permissão com targets, `implied_by`, `depends_on`, campos e labels por locale, e num papel ou kind.
- **Ir para definição** de permissão, papel, grant ou sujeito entre arquivos.
- **Code action** "Convert to rules/actors/blocks syntax" para o arquivo inteiro.

```sh
cargo install --git https://github.com/The-Hades-Organization/Strig strig-lsp --locked   # o servidor
cargo install strig-cli --locked                                                            # `strig test`, para o comando abaixo
```

A extensão procura `strig-lsp` e `strig` no `PATH`, ou em `strig.server.path` e `strig.cli.path`, e explica como instalar quando faltam. O comando "Strig: Run policy tests" roda `strig test .` na pasta do arquivo aberto. Para montar a extensão: `cd editors/vscode && npm ci && npm test && npx vsce package`. A publicação no Marketplace e no Open VSX ainda não está configurada. Outros editores com LSP podem rodar `strig-lsp` direto: ele fala por stdio e não recebe argumentos.

### Macros

`policy!` e `include_policy!`, do crate `strig-macros`, validam a política em tempo de compilação: política que não valida não compila. Elas ficam num crate próprio, e não atrás de uma feature do `strig`; o guia explica [por quê](docs/dsl.md#macros).

```rust
use strig_macros::{include_policy, policy};

let inline: strig::dsl::Policy = policy!(r#"
language blocks

target_kinds = [org]

permission org.read {
  targets = [org]
}
"#);
let from_file: strig::dsl::Policy = include_policy!("policies/main.strig");
```

## Migrando do Casbin / OpenFGA

`strig import` lê o modelo e a política de outra biblioteca e escreve um arquivo `.strig`. Nada roda o Casbin nem o OpenFGA: o conversor é um módulo da biblioteca (feature `import`, ligada no `strig-cli`, sem IO) que recebe texto e devolve uma política e um relatório.

```sh
strig import casbin model.conf policy.csv -o ./policy [--language blocks|rules|actors] [--action read]...
strig import openfga model.fga tuples.csv -o ./policy [--language blocks|rules|actors]
```

Escreve `<dir>/policy.strig` e imprime o que foi convertido, o que foi convertido com alcance menor e o que não foi. Sai com `0` quando tudo converteu, `1` quando algo não tem tradução fiel (nada é escrito) e `2` para erro de uso. O resultado se confere como qualquer política: rode `strig test`.

**Casbin.** ACL, RBAC (`g = _, _`, e domínios com `g = _, _, _`), RBAC com `keyMatch` no recurso e ABAC sobre atributos são lidos. Uma linha `p` vira grants, uma linha `g` vira atribuição de papel ou aresta do grafo de papéis, e o efeito da política escolhe a estratégia (`some(where (p.eft == allow))` é `most_specific`, com a linha `deny` descartada e relatada; `!some(where (p.eft == deny))`, allow-and-deny e `priority(p.eft)` viram `deny_overrides` ou `first_applicable`). Um modelo que não restringe a ação (ABAC) pede `--action <nome>`. `keyMatch` vira condição `starts_with` e `regexMatch` só é lido sobre alternâncias de literais, expandidas pelas ações que a política cita. Um matcher sem tradução fiel (`keyMatch2`, `globMatch`, aritmética, `!=` entre pedido e política) é um erro com arquivo, linha e coluna e o motivo, nunca uma aproximação que permita mais.

**OpenFGA.** O DSL e o JSON do modelo são lidos, e as tuplas em JSON, CSV, YAML ou uma por linha. Tipos e relações viram um `RelationSchema` (`This`, `Computed`, `TupleToUserset`, `Union`, `Intersection`, `Exclusion`), as tuplas vão para o `TupleStore` e cada relação ganha uma permissão e um grant. Condições (CEL) não são traduzidas: modelo ou tupla que use uma é um erro que aponta para ela.

Cada fixture em `crates/strig/tests/fixtures/import/` traz um modelo, uma política e uma tabela de pedidos com as respostas da biblioteca de origem (da documentação dela); os testes decidem os mesmos pedidos com a política importada, nas três sintaxes, e comparam.

## Visualizador (`strig-inspect`)

O `strig-inspect` mostra por que uma decisão saiu como saiu. Ele usa `Engine::explain`, que Rust e JS também chamam direto. Com o cenário de exemplo:

```sh
strig-inspect explain --scenario crates/strig-inspect/examples/scenario.json \
    --subject ben --permission document.view --resource secret
```

```text
DENIED — ben asks document.view on document:secret → project:roadmap → org:acme → global
reason: grant no-secret (document.view, step 0) chosen by strategy most_specific
permissions that grant: document.view, project.view
effective roles: member
override resource_owner: abstained
grants (5):
  + members-view allow project.view → role member on org [step 2]
      candidate
  - editors-edit allow project.edit → relation editor on project
      permission not related
  ★ no-secret deny document.view → any subject on document:secret [step 0]
      candidate
  - pro-export allow document.export → role member on org
      permission not related
  - no-invoice-export deny document.invoice.export → role member on doc_type:invoice
      permission not related
```

O crate não está no crates.io e fica fora dos `default-members` do workspace. Instale a partir de um clone:

```sh
cargo install --path crates/strig-inspect                          # janela e comandos de terminal
cargo install --path crates/strig-inspect --no-default-features    # só comandos de terminal, sem gpui
```

```sh
strig-inspect --scenario scenario.json --audit trail.jsonl          # janela
strig-inspect --scenario scenario.json --subject ben --permission document.export --resource invoice-7 \
               --disable pro-export --tab matrix                    # janela aberta numa seleção e aba
strig-inspect matrix --scenario scenario.json --resource secret --disable no-secret --add grant.json
strig-inspect audit  --audit trail.jsonl --scenario scenario.json
strig-inspect fmt [--check] <arquivo|dir>
```

Um cenário é um arquivo JSON com a política (`spec`, um `EngineSpec`), os dados (`grants`, `tuples`, `env`) e os sujeitos e recursos a examinar, por nome. O exemplo em `crates/strig-inspect/examples/` vem com uma trilha forense de seis decisões, `audit.jsonl`, gerada por:

```sh
cargo run -p strig-inspect --no-default-features --example trail -- \
    crates/strig-inspect/examples/scenario.json > crates/strig-inspect/examples/audit.jsonl
```

A janela tem três abas:

- **Evaluation:** escolha sujeito, permissão e recurso e veja a decisão, o motivo, o caminho do recurso com o degrau que decidiu, os papéis efetivos, cada override e por que cada grant valeu ou não, com a árvore da condição e os valores resolvidos.
- **Matrix:** toda permissão do catálogo para todo sujeito num recurso. Clique numa célula para abrir o rastro dela.
- **Audit:** lê uma trilha JSON Lines, confere a cadeia de hash dos registros `forensic`, mostra o rastro gravado e reavalia as decisões `detailed` e `forensic` contra a política atual, apontando as que mudariam.

A **simulação** vale para todas as abas: desligue ou ligue grants, ou acrescente com `--add`, e veja se o conjunto daria o acesso. Quando uma decisão muda, a decisão original aparece ao lado, e as células alteradas da matriz ficam marcadas.

Os arquivos recarregam quando mudam no disco. A janela segue o tema claro ou escuro do sistema, usa a paleta do playground e embute as fontes (Noto Sans e JetBrains Mono, OFL) e os ícones, então fica igual em qualquer máquina. A interface é em inglês.

### No navegador

O playground também hospeda o visualizador: [strig-playground.vercel.app/inspector.html](https://strig-playground.vercel.app/inspector.html). Ele tem as mesmas três abas e a mesma simulação, sobre o motor compilado para WebAssembly, então não há nada para instalar. Lê o mesmo JSON de cenário do `strig-inspect`, de um arquivo, de um texto colado ou do exemplo embutido (`crates/strig-inspect/examples/scenario.json`).

- **Evaluation:** a decisão, o motivo, o caminho, os papéis efetivos, cada override e por que cada grant se aplicou ou não, sobre o `explain`.
- **Matrix:** cada permissão do catálogo para cada sujeito sobre um recurso. Clique numa célula para abrir a avaliação.
- **Audit:** carrega uma trilha JSON Lines, verifica a cadeia `forensic` com `verifyAuditChain` e reavalia as decisões `detailed` e `forensic` contra a política atual, marcando as que mudariam.
- **Simulação:** desligue grants ou adicione outros por um formulário; quando uma decisão muda, a original aparece ao lado, e as células alteradas da matriz ficam marcadas.

A página usa a identidade do playground, segue o tema claro ou escuro e funciona a partir de 360 px de largura. O cenário e a trilha são lidos na própria página e nunca saem do navegador. Para rodar localmente, veja [`playground/README.md`](playground/README.md).

## Pontos de extensão

| Trait | Implemente para |
|---|---|
| `GrantSource` | Ler grants de um banco, de um cache ou de várias fontes (tuplas `(A, B)` encadeiam). |
| `TupleStore` | Guardar tuplas ReBAC fora da memória. |
| `Override` | Decidir antes dos grants: dono, superadmin, conta suspensa, janela de manutenção. `FnOverride` recebe uma closure. |
| `Strategy` | Combinar grants com outra regra. |
| `Invariant` | Acrescentar uma regra para mudanças de grant. |
| `CatalogRule` | Validar o catálogo do seu jeito (`RequireMeta`, `FnRule`). |
| `AuditSink` | Mandar a trilha de auditoria para outro lugar. |
| `Transport` | Levar os avisos de mudança entre instâncias. |
| `CapabilityProvider`, `GrantLoader` | Controlar como uma sessão calcula as capacidades que envia. |
| `ChangeSink` | Reagir de forma síncrona a cada mudança (cache, métrica). |

## Desenvolvimento

```sh
cargo fmt --all --check
cargo clippy --workspace --exclude strig-inspect --exclude strig-python --all-targets -- -D warnings
cargo test --workspace --exclude strig-inspect --exclude strig-python
cargo test -p strig-inspect --no-default-features

# transportes contra servidores reais (pulados sem as variáveis)
STRIG_REDIS_URL=redis://127.0.0.1:6379/ STRIG_PG_URL=postgres://postgres:pw@127.0.0.1/postgres \
    cargo test --workspace --exclude strig-inspect
```

O pacote npm fica em `crates/strig-node/js`. `crates/strig-node/scripts/build.sh` gera o módulo nativo (`js/native/strig.<plataforma>-<arch>.node`, o fallback de build local do loader) e o WebAssembly (`js/wasm/`); a release separa os módulos nativos em pacotes por plataforma com `scripts/package-platforms.mjs`; a parte wasm precisa do target `wasm32-unknown-unknown` e do `wasm-bindgen-cli` 0.2.130.

```sh
sh crates/strig-node/scripts/build.sh
cd crates/strig-node/js
npm ci
npm test              # Node
npm run test:bun      # Bun
```

Defina `STRIG_RUST_SERVER` com a URL do exemplo `server` do `strig-axum` para testar também o cliente JS contra o servidor Rust.

Para rodar o playground localmente, veja [`playground/README.md`](playground/README.md).

Compilar a janela do `strig-inspect` no Linux exige as bibliotecas de desenvolvimento de Wayland e X11, por exemplo `libxkbcommon-dev`, `libwayland-dev`, `libxcb1-dev` e `libvulkan-dev`.

Medições: `cargo bench -p strig --bench engine` e `node bench/bench.mjs` em `crates/strig-node/js` (ou `bun`); veja [docs/benchmarks.md](docs/benchmarks.md).

Fuzzing: `./fuzz/run.sh <alvo> [segundos]` (nightly e `cargo install cargo-fuzz`) roda os alvos de `fuzz/` para a linguagem de políticas, `EngineSpec`, condições, decisões, as mensagens do sync e do server e a cadeia de auditoria; veja o [CONTRIBUTING.md](CONTRIBUTING.md#contribuindo-com-a-strig).

Os comentários do código são em português do Brasil. Issues e pull requests são bem-vindos em inglês ou português; veja o [CONTRIBUTING.md](CONTRIBUTING.md).

## Licença

[MIT](LICENSE). As fontes embutidas no `strig-inspect` estão sob a SIL Open Font License 1.1 (veja `crates/strig-inspect/assets/fonts`).
