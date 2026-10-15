# Log de Auditoria Encadeado

> Trilha de auditoria append-only com cadeia de hashes SHA-256 (ou HMAC): qualquer edição ou remoção é detectada. Prova técnica pra LGPD, compliance e disputa com cliente.

**Ver ao vivo, com preview e manual:** https://flowcoresolucoes.com.br/codigos/log-de-auditoria

Criado por **FlowCore Soluções LTDA**.

## Arquivos

- [`src/log-auditoria.ts`](src/log-auditoria.ts)
- [`src/log-auditoria.test.ts`](src/log-auditoria.test.ts)

## Como instalar

1. **Funciona onde você já roda** Node 18+, Cloudflare Workers, Deno, Bun, Vercel e Netlify Functions. Zero dependência: só fetch e Web Crypto, que já vêm no runtime.
2. **Crie src/lib/log-auditoria.ts** Copie o conteúdo de `src/log-auditoria.ts` e `src/log-auditoria.test.ts` deste repositório.
3. **Use**

   ```bash
   const auditoria = criarLogAuditoria({ armazem: meuArmazemPostgres, chaveHmac: env.AUDIT_KEY });
   await auditoria.registrar({ ator: "u_42", acao: "pedido.cancelado", recurso: "pedido:981", dados: { motivo } });
   const r = await auditoria.verificar();
   if (!r.valido) alertar(`Log adulterado na linha ${r.seq}`);
   ```

4. **Rode o teste junto** O arquivo de teste (`src/log-auditoria.test.ts`) cobre 9 cenários. Copie para src/lib/ ao lado e rode:

   ```bash
   npm install -D vitest
   npx vitest run src/lib
   ```


## Testes

`src/log-auditoria.test.ts` cobre 9 cenários.

```bash
npm install
npm test
```

## Licença

MIT. Pode usar em projeto pessoal ou comercial, de graça. A única condição é manter a linha **“Criado por FlowCore Soluções LTDA”** (ou o crédito de adaptação) onde ela está.

---

Precisa disso integrado no seu sistema? A [FlowCore](https://flowcoresolucoes.com.br) desenvolve sob medida.
