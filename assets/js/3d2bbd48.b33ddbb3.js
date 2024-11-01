"use strict";(self.webpackChunkwebsite_docs=self.webpackChunkwebsite_docs||[]).push([[1404],{5812:(e,r,o)=>{o.r(r),o.d(r,{assets:()=>i,contentTitle:()=>c,default:()=>d,frontMatter:()=>s,metadata:()=>a,toc:()=>p});var n=o(4848),t=o(8453);const s={},c=void 0,a={id:"grpc-proxy/enable-peers",title:"enable-peers",description:"Enable GRPC proxy for Fabric Operations Console",source:"@site/docs/grpc-proxy/enable-peers.md",sourceDirName:"grpc-proxy",slug:"/grpc-proxy/enable-peers",permalink:"/bevel-operator-fabric/docs/grpc-proxy/enable-peers",draft:!1,unlisted:!1,editUrl:"https://github.com/hyperledger-bevel/bevel-operator-fabric/edit/master/website/docs/grpc-proxy/enable-peers.md",tags:[],version:"current",frontMatter:{},sidebar:"mainSidebar",previous:{title:"Using custom CouchDB image",permalink:"/bevel-operator-fabric/docs/couchdb/custom-image"},next:{title:"enable-orderers",permalink:"/bevel-operator-fabric/docs/grpc-proxy/enable-orderers"}},i={},p=[{value:"Enable GRPC proxy for Fabric Operations Console",id:"enable-grpc-proxy-for-fabric-operations-console",level:2}];function l(e){const r={code:"code",h2:"h2",p:"p",pre:"pre",...(0,t.R)(),...e.components};return(0,n.jsxs)(n.Fragment,{children:[(0,n.jsx)(r.h2,{id:"enable-grpc-proxy-for-fabric-operations-console",children:"Enable GRPC proxy for Fabric Operations Console"}),"\n",(0,n.jsxs)(r.p,{children:["In order to enable the GRPC Web, needed to connect the peer to the Fabric Operations console, we need to add the ",(0,n.jsx)(r.code,{children:"grpcProxy"})," property with the following attributes:"]}),"\n",(0,n.jsx)(r.pre,{children:(0,n.jsx)(r.code,{className:"language-yaml",children:"  grpcProxy:\n    enabled: true\n    image: ghcr.io/hyperledger-labs/grpc-web\n    tag: latest\n    imagePullPolicy: Always\n    istio:\n      port: 443\n      hosts:\n       - <YOUR_HOST>\n      ingressGateway: 'ingressgateway'\n    resources: \n      limits:\n        cpu: '200m'\n        memory: 256Mi\n      requests:\n        cpu: 10m\n        memory: 256Mi\n"})})]})}function d(e={}){const{wrapper:r}={...(0,t.R)(),...e.components};return r?(0,n.jsx)(r,{...e,children:(0,n.jsx)(l,{...e})}):l(e)}},8453:(e,r,o)=>{o.d(r,{R:()=>c,x:()=>a});var n=o(6540);const t={},s=n.createContext(t);function c(e){const r=n.useContext(s);return n.useMemo((function(){return"function"==typeof e?e(r):{...r,...e}}),[r,e])}function a(e){let r;return r=e.disableParentContext?"function"==typeof e.components?e.components(t):e.components||t:c(e.components),n.createElement(s.Provider,{value:r},e.children)}}}]);