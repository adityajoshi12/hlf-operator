"use strict";(self.webpackChunkwebsite_docs=self.webpackChunkwebsite_docs||[]).push([[59],{4900:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>n,default:()=>d,frontMatter:()=>i,metadata:()=>p,toc:()=>s});var o=r(4848),a=r(8453);const i={id:"deploy-operator-ui",title:"Deploy Operator UI"},n=void 0,p={id:"operator-ui/deploy-operator-ui",title:"Deploy Operator UI",description:"Create operator UI",source:"@site/docs/operator-ui/deploy-operator-ui.md",sourceDirName:"operator-ui",slug:"/operator-ui/deploy-operator-ui",permalink:"/bevel-operator-fabric/docs/operator-ui/deploy-operator-ui",draft:!1,unlisted:!1,editUrl:"https://github.com/hyperledger-bevel/bevel-operator-fabric/edit/master/website/docs/operator-ui/deploy-operator-ui.md",tags:[],version:"current",frontMatter:{id:"deploy-operator-ui",title:"Deploy Operator UI"},sidebar:"mainSidebar",previous:{title:"Getting started",permalink:"/bevel-operator-fabric/docs/operator-ui/getting-started"},next:{title:"Deploy Operator API",permalink:"/bevel-operator-fabric/docs/operator-ui/deploy-operator-api"}},l={},s=[{value:"Create operator UI",id:"create-operator-ui",level:2},{value:"Create operator UI with authentication",id:"create-operator-ui-with-authentication",level:2},{value:"Update operator API",id:"update-operator-api",level:2},{value:"Delete operator UI",id:"delete-operator-ui",level:2}];function c(e){const t={code:"code",h2:"h2",p:"p",pre:"pre",...(0,a.R)(),...e.components};return(0,o.jsxs)(o.Fragment,{children:[(0,o.jsx)(t.h2,{id:"create-operator-ui",children:"Create operator UI"}),"\n",(0,o.jsx)(t.p,{children:"In order to create the operator UI:"}),"\n",(0,o.jsx)(t.pre,{children:(0,o.jsx)(t.code,{className:"language-bash",children:'export HOST=operator-ui.<domain>\nexport API_URL="http://api-operator.<domain>/graphql"\nkubectl hlf operatorui create --name=operator-ui --namespace=default --hosts=$HOST --ingress-class-name=istio --api-url=$API_URL\n'})}),"\n",(0,o.jsx)(t.h2,{id:"create-operator-ui-with-authentication",children:"Create operator UI with authentication"}),"\n",(0,o.jsx)(t.pre,{children:(0,o.jsx)(t.code,{className:"language-bash",children:'export HOST=operator-ui.<domain>\nexport API_URL="http://api-operator.<domain>/graphql"\nexport OIDC_AUTHORITY="<url_authority>" # without the /.well-known/openid-configuration\nexport OIDC_CLIENT_ID="<client_id>" # OIDC Client ID for the Operator UI\nexport OIDC_SCOPE="profile email" # OIDC Scope for the Operator UI\nkubectl hlf operatorui create --name=operator-ui --namespace=default --hosts=$HOST --ingress-class-name=istio --api-url=$API_URL \\\n      --oidc-authority="${OIDC_AUTHORITY}" --oidc-client-id="${OIDC_CLIENT_ID}" --oidc-scope="${OIDC_SCOPE}"         \n'})}),"\n",(0,o.jsx)(t.h2,{id:"update-operator-api",children:"Update operator API"}),"\n",(0,o.jsxs)(t.p,{children:["You can use the same commands with the same parameters, but instead of ",(0,o.jsx)(t.code,{children:"create"})," use ",(0,o.jsx)(t.code,{children:"update"})]}),"\n",(0,o.jsx)(t.h2,{id:"delete-operator-ui",children:"Delete operator UI"}),"\n",(0,o.jsx)(t.p,{children:"In order to delete the operator UI:"}),"\n",(0,o.jsx)(t.pre,{children:(0,o.jsx)(t.code,{className:"language-bash",children:"kubectl hlf operatorui delete --name=operator-ui --namespace=default\n"})})]})}function d(e={}){const{wrapper:t}={...(0,a.R)(),...e.components};return t?(0,o.jsx)(t,{...e,children:(0,o.jsx)(c,{...e})}):c(e)}},8453:(e,t,r)=>{r.d(t,{R:()=>n,x:()=>p});var o=r(6540);const a={},i=o.createContext(a);function n(e){const t=o.useContext(i);return o.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function p(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(a):e.components||a:n(e.components),o.createElement(i.Provider,{value:t},e.children)}}}]);