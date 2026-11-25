// Small selectors for the static, non-nested blocks checked by the HTML audits.
// Attribute order, quote style and extra CSS classes are presentation details.
export function elements(html, tag) {
  return [...html.matchAll(new RegExp('<' + tag + '\\b([^>]*)>([\\s\\S]*?)</' + tag + '\\s*>', 'gi'))]
    .map(([, attributes, content]) => ({
      attributes: Object.fromEntries([...attributes.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)]
        .map(([, name, doubleQuoted, singleQuoted]) => [name, doubleQuoted ?? singleQuoted])),
      content
    }));
}

export function hasClass(element, name) {
  return (element.attributes.class || '').split(/\s+/).includes(name);
}

export function textContent(element) {
  return element.content.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}
