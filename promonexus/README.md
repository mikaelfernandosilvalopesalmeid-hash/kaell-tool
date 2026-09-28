# PromoNexus — site para GitHub Pages

Site estático, responsivo e pronto para GitHub Pages.

## Publicar

1. Crie um repositório público no GitHub (ex.: `promonexus`).
2. Envie **o conteúdo desta pasta** para a raiz do repositório.
3. No GitHub: **Settings → Pages**.
4. Em **Build and deployment**, escolha **Deploy from a branch**.
5. Selecione `main` e `/ (root)`.
6. Salve e aguarde o endereço `https://SEUUSUARIO.github.io/promonexus/`.

## Depois do primeiro deploy

Substitua `BASE_URL` em:
- `sitemap.xml`
- `robots.txt`

pelo endereço real do site.

## Antes de usar no cadastro da Amazon

- Deixe o repositório/site públicos.
- Abra todos os 10 guias e confira se carregam.
- Não adicione links de afiliados antes de ter os dados corretos.
- Quando a conta de afiliado estiver ativa, mantenha a divulgação de afiliado clara no site.
- Use conteúdo real e atualizado; não transforme o site em uma página vazia só para cadastro.

## Estrutura

- `index.html` — home
- `sobre.html`
- `privacidade.html`
- `termos.html`
- `artigos/` — 10 guias originais
- `assets/` — CSS, JS e logo
- `404.html`, `robots.txt`, `sitemap.xml`

## Referências de design aplicadas

- frontend-design (Anthropic): hierarquia visual, layout editorial, responsividade, acessibilidade
- Humanizer: textos mais naturais e menos “texto de IA”
- React Bits: inspiração em motion, aurora, cards/spotlight, reveal
- 21st.dev: referências de hero, bento, navegação e marketing blocks
- Uiverse: microinterações, botões, chips, glass cards e hover states

Nenhum componente premium/proprietário foi copiado. Os efeitos foram implementados do zero em HTML/CSS/JS.
