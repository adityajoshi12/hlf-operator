"use strict";(self.webpackChunkwebsite_docs=self.webpackChunkwebsite_docs||[]).push([[2989],{8500:(e,r,o)=>{o.r(r),o.d(r,{assets:()=>t,contentTitle:()=>c,default:()=>a,frontMatter:()=>s,metadata:()=>d,toc:()=>A});var i=o(4848),n=o(8453);const s={id:"adding-orderers",title:"Adding Orderer nodes"},c=void 0,d={id:"operations-console/adding-orderers",title:"Adding Orderer nodes",description:"The steps to follow to add a Ordering Service to the Fabric Operations console are:",source:"@site/docs/operations-console/adding-orderers.md",sourceDirName:"operations-console",slug:"/operations-console/adding-orderers",permalink:"/bevel-operator-fabric/docs/operations-console/adding-orderers",draft:!1,unlisted:!1,editUrl:"https://github.com/hyperledger-bevel/bevel-operator-fabric/edit/master/website/docs/operations-console/adding-orderers.md",tags:[],version:"current",frontMatter:{id:"adding-orderers",title:"Adding Orderer nodes"},sidebar:"mainSidebar",previous:{title:"Adding Peers",permalink:"/bevel-operator-fabric/docs/operations-console/adding-peers"},next:{title:"Adding Organizations",permalink:"/bevel-operator-fabric/docs/operations-console/adding-orgs"}},t={},A=[{value:"Export Ordering Service to JSON",id:"export-ordering-service-to-json",level:2},{value:"Enter the Fabric Operations Console UI",id:"enter-the-fabric-operations-console-ui",level:2},{value:"Go to <code>Nodes</code>",id:"go-to-nodes",level:2},{value:"Click on <code>Import Ordering services</code>",id:"click-on-import-ordering-services",level:2},{value:"Select the JSON from the file system",id:"select-the-json-from-the-file-system",level:2},{value:"Click on <code>Add Ordering services</code>",id:"click-on-add-ordering-services",level:2}];function l(e){const r={code:"code",h2:"h2",img:"img",li:"li",p:"p",pre:"pre",ul:"ul",...(0,n.R)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(r.p,{children:"The steps to follow to add a Ordering Service to the Fabric Operations console are:"}),"\n",(0,i.jsxs)(r.ul,{children:["\n",(0,i.jsx)(r.li,{children:"Export Ordering Service to JSON format"}),"\n",(0,i.jsx)(r.li,{children:"Enter the Fabric Operations Console UI"}),"\n",(0,i.jsxs)(r.li,{children:["Go to ",(0,i.jsx)(r.code,{children:"Nodes"})]}),"\n",(0,i.jsxs)(r.li,{children:["Click on ",(0,i.jsx)(r.code,{children:"Import Ordering services"})]}),"\n",(0,i.jsx)(r.li,{children:"Select the JSON from the file system"}),"\n",(0,i.jsxs)(r.li,{children:["Click on ",(0,i.jsx)(r.code,{children:"Add Ordering services"})]}),"\n"]}),"\n",(0,i.jsx)(r.h2,{id:"export-ordering-service-to-json",children:"Export Ordering Service to JSON"}),"\n",(0,i.jsx)(r.pre,{children:(0,i.jsx)(r.code,{className:"language-bash",children:'export ORDERER_NAME=orderer0-ordmsp068wi-5vph\nexport ORDERER_NS=default\nkubectl hlf fop export orderer --cluster-id=orderermsp1 --cluster-name="Cluster 1" --name=$ORDERER_NAME --namespace=$ORDERER_NS --out="${ORDERER_NAME}_${ORDERER_NS}.json"\n'})}),"\n",(0,i.jsx)(r.h2,{id:"enter-the-fabric-operations-console-ui",children:"Enter the Fabric Operations Console UI"}),"\n",(0,i.jsx)(r.p,{children:"Open a browser and navigate to the URL you configured when creating the Fabric Operations Console."}),"\n",(0,i.jsxs)(r.h2,{id:"go-to-nodes",children:["Go to ",(0,i.jsx)(r.code,{children:"Nodes"})]}),"\n",(0,i.jsxs)(r.p,{children:["Click on ",(0,i.jsx)(r.code,{children:"Nodes"})," at the sidenav to see the Peers, Certificate Authorities and Ordering Services"]}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.img,{alt:"img_1.png",src:o(4138).A+"",width:"398",height:"117"})}),"\n",(0,i.jsxs)(r.h2,{id:"click-on-import-ordering-services",children:["Click on ",(0,i.jsx)(r.code,{children:"Import Ordering services"})]}),"\n",(0,i.jsxs)(r.p,{children:["Click on ",(0,i.jsx)(r.code,{children:"Import Ordering services"})," to open the dialog to import the Ordering Service."]}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.img,{alt:"img.png",src:o(6083).A+"",width:"1327",height:"472"})}),"\n",(0,i.jsx)(r.h2,{id:"select-the-json-from-the-file-system",children:"Select the JSON from the file system"}),"\n",(0,i.jsxs)(r.p,{children:["Click on ",(0,i.jsx)(r.code,{children:"Add file"})," and select the JSON file you exported from the step ",(0,i.jsx)(r.code,{children:"Export ordering services to JSON"}),"."]}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.img,{alt:"img.png",src:o(5603).A+"",width:"545",height:"969"})}),"\n",(0,i.jsxs)(r.h2,{id:"click-on-add-ordering-services",children:["Click on ",(0,i.jsx)(r.code,{children:"Add Ordering services"})]}),"\n",(0,i.jsxs)(r.p,{children:["The last step is to set ",(0,i.jsx)(r.code,{children:"Ordering service location"})," to Kubernetes and to click on ",(0,i.jsx)(r.code,{children:"Add Ordering services"})," and the Ordering Service will be imported to the console."]}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.img,{alt:"img.png",src:o(7979).A+"",width:"553",height:"971"})})]})}function a(e={}){const{wrapper:r}={...(0,n.R)(),...e.components};return r?(0,i.jsx)(r,{...e,children:(0,i.jsx)(l,{...e})}):l(e)}},7979:(e,r,o)=>{o.d(r,{A:()=>i});const i=o.p+"assets/images/add_ordering_service-c33e4dab4157db62afa37a215e90e727.png"},4138:(e,r,o)=>{o.d(r,{A:()=>i});const i="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAY4AAAB1CAYAAABZJgYSAAAU2klEQVR4Xu2diZMURb7H9x9YNyAw1I3dDV0JILgChFDRUEEI4IEE1wNd0VgXnri4iiD35QWILKK7K5cgKIrLPa4ohyCHXHIKzADC80CR462ogCGLCPh788uerMn+VWV111DMZFV/K+IT3ZX5y+xqqPp9OjOre37Rqm07Yho1uZGqX3UNAAAAEMovysXR1FcJAAAASAxxYMQBAAAgNxAHAACASEAcAAAAIgFxAAAAiATEAQAAIBIQBwAAgEhAHAAAACIBcQAAAIgExAEAACASEAcAAIBIQBwAAAAiAXEAAACIBMQBAAAgEhAHAACASHjiaDCA6Fc9f1ZcV7suAABUGTJRAbeAOAAAziETFXALiAMA4BwyUQG3KBfH4xlppEIcter4ywAAiUEmKuAW6RtxsDQgDgASjUxUwC0McaRgxFEmjWshDgASjUxUwC2MqaqLyRaHIQ2IA4BkIxMVcIt0TFUJaUAcACSb6lde7UtWwB3SMeIQ0oA4qo7f16mnkOUAREGJA/JwluSPOAJGGxBH1QFxgDiopsUBeThJKsQhpZE0cehkGzXpVqTN5ca14wHJhMXhySMgcYGqJdnf47CMNiCOqsO14wHJRIsD8nCTZI84AoSRBnHkm3ijxlcGrh0PSCYQh9tAHA4gpZFv4o0aXxm4djwgmZjigDzcI7l3VbEcAoSRFnHkk3yjxFYWrh0PSCYQh9skd8QRIIs0iCNo30a+cUHxUdpJwvoIKgsjrK98kO0r0gdwD4jDbdIpjpq1/fEOI5Oe3LdRkTgbsk0Qso3EjJFtJbKtRMZLZHwQsg1IDhCH2xhTVRcuSRzTX5lJQdvOXbvoTw8+lBXLZUEb9yH7tSJlkSJx2MokUWPMWFkW1oc93l9Wkb5ylUtknI6VZWF9ALeR4oA83CK2HznkjYXAyd+EN1McukzGaZnIfq1IWUAcPnLVZ8gdY/aTb5ysizPGq68dXK9jZBlIDlIaEIdbxDZVZRsxyHItDhlnK7ciZZEycYSVx1Wfb1yu+nzjctUHxcryXHUgHUhpQBxuEdtdVVIQtnKbIGzlgdQKv6MqKeJ4oNeDNHzUk9SgyY3WZBiWbCtaF4QtNq5+ovYVFmsrB+lBSgPicIv0iaNUGnGKo/fDf6E9xcW0bv0GqlW/oVfes/efVXn/QYN9bfJlzdp19PPPP1OL1m2tyTCfBBq1LghbvK3cRlhsWJ0k7HXD6kA6kNKAONwimVNVlSiOoSNHqeTO/GPyFK98wOChqmzc+Am+NvmSjzgYW6K0leeqC8IWbyu3ERZr9hWFfPuRcSC5SGlAHG4R229V2e6U4s0UBy+U2zbuQ/YbSBWI47vvvqOzZ89Sy9J/Ky4PEkff/gPowMGDdObMGSouKaEeD/TM6uvhvo/RoS++oBMnvqG/T5rsE0fNeg1o8rSX6fBXX9HJU6do7Qfr6dYWd3qJsXO37rRr1276z3/OquOZv3AR1b+haWDSjJpQbfG2chv2WH+izxd/X3Z5hLUByUFKA+Jwi9jEwbAgJPJW3LC4oNhAqkAcfIznz5+nTR9+qMqlOP7Y63/o4sWLKuG/v2aNksdPP/1Erdvdpeqb3dFC7XObHTt30v9+8gn937//nSWOqdNnqP2SvXvpX0uW0Llz5+jzQ4fo+rr1Vf2XXx4uldePqm77jp104cIF6vVQn8BEGTWJ2uJt5TbCYqP2lS9mvxIZC5KBlAbE4RaxTVVVKlUgjmfGPktL3l2qng8eNtwnjvUbN6r9Lt3vUfs8+uB9HhXw/vgJz6v9f86br/Y5qX3xxZeeOHi08cMPP9A333zjJby58xeo+j6P9KW6jW5QomBh8Kd3rm/fqYs1QUZNnrZ4W7mNsNiwujiJeszAPaQ0IA63iHXEUWlUkThatPkvNQr46sgRJQ9THEePHlOJX7e74eZbMqOLjz5S+3Pmzs1I4NG+Xow5VcV988b9zFuwULF123ZVP/Fvf1fxm7dsUTE8Wnlz7jxq17GTNUFGTZ62eFu5jbDYsLq4qczXAvEjpQFxuEVsIw491SSnoMz1DTNWxgTFWZGyqCRx8P7sN+ao/VWrV2eJg9cteJpKt+O1B64v2bdP7S9YtFjt93roz16MKQ6WAG/Hjx9XIxsTfecWy2VOqTC+/fZbFctteYrMliCjJM+w2LA6SVisrrPVx0llvhaIHykNiMMtYrsdN2xxPOib40FblMVxnzAqSRw8kjh16rSaNjLFwYvWvH9Hy9ZqnxfGeX/ZihVq/6XJU9S+eWfWrt17PHHUadhY9Xns2PGs17/9zlZZz/V6B98OzNvioresyTHf5JkrLld9lLhc9fnEhdVFiQHuIqUBcbhFbOLgLWjUIMu1OGScrTwQKYtKFAcz4YUXVZkSx18z4hj55FNqf8vWbfT0mLG0b//Hal9Ls2PXbmr/5MmTNHnqNDV1xXdpaXFwktNrKCtWrqKhI0bS8hXv0dcnTlCTZrfSbS1aqlENr6UMGjqcXp/zpvdvG5YgcyXzXPX5xpn1tph84i61XsbIOpAMpDQgDreIbapKCsJWbhOErTwQKYtKFkftBo3oyNGjWeLgkcDMV19TayBczndV8YK42RffasujCr77iqe61q77IEscTW+5jVavWeuNZr4rlQxLittyPQuHRztcxxt/KbFh2bfO5XGbyGQbhGwjkfFBmHGyfdS+wvqQcTZkO5AcpDQgDrfAiCNmatVrQM1LRcAikXVMvcZN6KZbb88qk8mO10d4hCHbapq3akONbrzZ1y4MmVSjtM2nH1kv20lke4mMD0K2idoeuIuUBsThFhhxAACcQ0oD4nCLWMVh+1l1Uxz6m+MyLtLPqktZQBwApAopDYjDLWITh5aE3OSdUiwO2x1YQSOWQKQsIA4AUoWUBsThFon9AqBPGBAHAKlBSgPicIvYRhyVipQFxAFAqpDSgDjcwhAHRhwAADeQ0oA43CK223ErFSkLiAOAVCGlAXG4BaaqAADOIaUBcbgFRhwAAOeQ0oA43CKxIw6rPCAOABKPlAbE4RYQBwDAOaQ0IA63SOz3OCAOANKLlAbE4RYYcQAAnENKA+JwC4gDAOAcUhoQh1sk9q4qiAOA9CKlAXG4RfpGHGXy8LUBACQGKQ2Iwy2SKQ5GygLiACA1SGlAHG5hTFVdgDgAAE4gpQFxuEUyf+SQkbKAOABIDVIaEIdbYKoKpIdambUvX7mNsHhbeRhh/YFIQBpu44mjUZMbfZWJIeDTiZ2rqFoNO78CAMSGvL6y4GvRd30GA3G4RQGKgwk4iSMgLw7gClfm2LdQXcTJ/bypaLtkIq+LSESQBgNxuEWBioMpO3nlCQ0SyJXqkRM+P1eP6rko4ziWgkDFms/L+jXb6jozXsXpMvlaWWXljwWPvu5812M4EIdbpEMcTMDJlh/GySxPcuAg/sSfFPzvpUAwrzHf9ZcbSMM9II4s5EkOXENNB1WvQVd4VKcrqlUvf7xcVLR/bqfIHC8fv3xP6UdeZ9GAONwjPeJgAk46kBJqlM2tl35yLyneR7t3F9Pekv1UvGevj0x5iXosKeayEtqzu4RKSvapem7LfZjxuk0mfq/3mOlnn2rPZPqs+OtfwaMP9Sk84D0CH5CGm6ROHJBHGskkWk64/Kmdk/NHO3cljow4eNQBceSDvp591zmoctIlDqbsZJMnIUg2+k4eTrz8KV4m5SSwp3TkcUW1jDi8O5MC3iuANFwnfeJgyk46eTKCZKJv/VTiqJbgEUfxvixxZBaO/e+30IE03Ced4mDKTj55UoKEYXw61+LgBCyTcty8v2oNvbNkqa/8UmDh+UYckEcWkEYySK84mLKTUJ6cIEEYow2+I+mXpYmXF5plUmY2bdxMrVq1ptdnz8kq79HjPnqr6G1ffBjTpk2nIUOG+covBRbeL6tVhzgsQBrJId3i0JSdkPJEBQkga8SREQffrSSTMrNxwyYlDmb9Bxu9chZHUdG/fPFhQByVB4SRPApDHBrzJA04gYGbmImWxWGbqtLiGDJ4KPXr198rN8Uxe/YbdP9991OHDh1p4IBBtHnTFlW+c8cueubp0dSxtPzee3vQsKHDPXF8uHkrDRw4iO66qwP1/FNPb/TCcnr00b5em4ULF/uOySQjjhqZLwQWsDjkdei7ToHzFJY4JPIEBk7ifQO5NOHyl+r27C72JWVGi4OnrLp1606vzJilyrU4Vq18XyX/oqK3lDAGDxpCw4eNUDHTX56hkv/aNeto1arV1L20vRbHyBGjlEi4DYunU6fOtH3bTpo48UUa8PhAJZ158xbQc+PG+47JJLPGUZ30T6Qw1TUB7zu1yOsQJI7CFgdwnqxPqzXCv8ehxbFj+0e0aGGRGlWsWb3OEweLpN9j5SMRXvxmQfDzoUOH0Uv/mOTVPT9hoicO7pNHJywKhveXLl1Oc954U73GmNFjacH8hep15TGZ6Luq5ChDvmcAXAfiAA4jpjnKxJFrqkon8NGjx1CfPg+rkQSLg0cVj/cf4MVz8u/apat6zqOPSZOmeHUvlArCFMezY8fRzFdmKVgwH6zboOqWLV2hZMJyeqxvP98xmegvAJriwCdwkEQgDuA8mSTLyTb/EQfvb92yXYmBy1gcy5e9p9YjVr63SsU8+eRTau2CY1kavH7B6xmbNm2m+3rc74mDRxssIW7Dwhg18gkVM2PGTHrt1dkqZvGiIurcuYvvmEz07bi+EQfkARIGxAEcpXxOXI44ct2Oy2sOumzpu8uoTZu23oL21CnTVILnKabevR+iDeszd1/xmgULon279tSlc1fq3/9xTxy8CN77wd5KOrxGwiMMLl/y9jvUvfvdarqLBTVr1qu+YzLhu8GkOPT7879/ANwlVnFMmjJVcc+99/nqguA43UbWAcD4pqr4exx7gsWRLyyWLR9u85UzW7Zss65V8GgkqI5HH6asbKg1DkxVgRQQmzg4+fO2ffsO9ZiPDHScbiPrAcgSR46pKtcJEgfkAZJIbOLgTY80tAxkjImMMdsDoDGnc5IuDp5i459V1+KAMEBSiU0c5pQTCyEfcWhZmM9lHChgVGLNXucIu6vKddTiOItD/HEj3/sGwHFiEwcnfT3lpLcwEWhZ6C2fqS1QmJhJlr91zZ/cOQmzQHjBOXs/80eX+Ln+Y006Ttdn/uBS5g8t8XqJ/gNMul1xsdkm84efdD/Mpby++hOynjAw6gDJJDZxSOSIQi+aY4QBKoInjxpXqeSr/xQrL5Zr+HegLg+yb7kvy/h59rFljrd8mgqjDZBkLps4GHNUYS6CQxogEkaizZD5uQ7zxw/LH/lvkpc96udB6HpbjNlP0KPE7M87HvljhlIaEAdIJpdVHEFrHVomMhYAGzrJZsujXCIySbuCkgXjO2ZMU4Fkc9nFETSy0CMQWQ4KB7kmxs/zOSdkAtbyUI9mss5K3AHPvceydmZMEPI1fP0ExZe1MYWhCXhvACSFyyoOmyB4CxJKodHstjvo7NmzPk6f/p5K9u6lp54ZTTWu/rWvXZLRwtAfKsxbuPVo9KXJU3ztzG+S+6euqgq/GPLF//4ASA6XVRxB01JBZYXKLbc3V/8We4qL6eUZMzze/OdcOnb8uKqbOWuWr11SCbopwpSHLUaiEm9AMnYVPc0m3wcAScUQR1Nf5aViLo5HuVW3UNDi4N84knU80jh8+DCdP3+B6tZv6KtPIrzJEageaZhlelQi2wdjrBeU4Uvccv+q8nUT/TyrPKiPstfT7XScjrW9fvm0lPkcgGQT+4jDnHrQgtCJQCcIWSf7KBTCxMHMeGWmqu929z1Z5c1btqIRo55Q/44PP/Io1axTz9c2Smzr0v//Pn95hK7+ze/UPk+hma/52+uup4GDh9DUl6fT06PHUIdOXXx95CJIEGHY1seyMROxJSmXJXp/mT82O9GL8qx2ZX2asQHtAEgrsYmDL3K5hV345miEtyhJJS3kEse06TNU/d339lD7PAp5adJkunDhAn3//ff02eefl45IzqtprY6du2a1jRL76muz1eu0aNmaPv3sM/V8x46dqq7ZrbfTiRMnVNnx0rY//vijer5s+XIlFHnMNoIWv/n84LKg8yTaqAMAUJnEJg7z1ltOBrkuei0a83lQAkkzucTBSfzixYtUv9ENap8/9fP2/AsveovmjZveRAcPHqSvv/6arr2+ltc2SqwWx9Zt22jBwkU0YNBgb1SxdNkyJRwelfD+r397LfUfMEj10/SmZr5jtsGbLJMjUVkX1AYAUPXEJg7edALI56KXcuGtUMWxbft2enbccx6TJk+hjz8+oOrmL1ioYjn58yf+DRs2+voZMmy4ih333PjIsYwWx2P9B/jiDxw4QPv3f+wrjwpvQf+/YVNYvMkyAEDVE5s49NSTXgS3JQMTHW+OVgoJLQ658SjjqyNHlECuKf2Ez7FNbrpZ1bFYZD+16tZXi+jvvLs0ciyjxXFdzdq++LeXvKPqRo999pIW6W1rFjZxyA8WAAB3iE0cjJ6zDkoEQUSNTxtaHK+9/gb97vc1PbQsTP7Q434Vy9NG8nsfDG+7du+OHMuEiaNB4yZqxMEbC43v9FpcVER3tmrjiw3DtmZh+/+3lQMAqp5YxQGikWuNw4QXtHnjO6263fOHQNq2vytyLBMmDoanvv67+900fsLz9P7qNWrB/dy5c1SnXgNfbBhy1CE3Xa5Hr7I9AMANII4qJIo4eIqJt3w+hUeJZXKJQ6LF9MyYsb66MPTaV9hx5RMDAKhaII4qJIo4GL7r6eixY2o6yyznaaP1Gzaou6YqEhsmjhEjn8ganTA8fcWjDh7RyPhc6NGEORXFstBTWXJUAgBwD4ijCokqjnYdOqp1C74Vtm+//tS5azd6bvxf1R1U+/btz0r8UWJt4uCRy+eHDtGZM2do4ot/U3080LMXrV23Tq138PSVPMZ8YWnoGyl4gzAASA4QRxUSVRxM+46d6JNPP/US7qnTp2nlqlVUr2HjCsfaxMHUrlef3lu5Sn2JUG8nT55Ut/XKWABAYQBxJBS+NbZl67Z05TW/8dVJosTa4AVy/mb5bc3vDLzrCwBQOEAcAAAAIgFxAAAAiATEAQAAIBIQBwAAgEhAHAAAACIBcQAAAIgExAEAACAS/w+jUMilqogm8wAAAABJRU5ErkJggg=="},6083:(e,r,o)=>{o.d(r,{A:()=>i});const i=o.p+"assets/images/ordering_service_import-58b57262cdf21ebbbedd1469d53bfe22.png"},5603:(e,r,o)=>{o.d(r,{A:()=>i});const i=o.p+"assets/images/select_json_ordering_service-d2cdd45c1513631e5733a0170e557118.png"},8453:(e,r,o)=>{o.d(r,{R:()=>c,x:()=>d});var i=o(6540);const n={},s=i.createContext(n);function c(e){const r=i.useContext(s);return i.useMemo((function(){return"function"==typeof e?e(r):{...r,...e}}),[r,e])}function d(e){let r;return r=e.disableParentContext?"function"==typeof e.components?e.components(n):e.components||n:c(e.components),i.createElement(s.Provider,{value:r},e.children)}}}]);