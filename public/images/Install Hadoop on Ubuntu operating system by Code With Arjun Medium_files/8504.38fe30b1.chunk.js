var _____WB$wombat$assign$function_____ = function(name) {return (self._wb_wombat && self._wb_wombat.local_init && self._wb_wombat.local_init(name)) || self[name]; };
if (!self.__WB_pmw) { self.__WB_pmw = function(obj) { this.__WB_source = obj; return this; } }
{
  let window = _____WB$wombat$assign$function_____("window");
  let self = _____WB$wombat$assign$function_____("self");
  let document = _____WB$wombat$assign$function_____("document");
  let location = _____WB$wombat$assign$function_____("location");
  let top = _____WB$wombat$assign$function_____("top");
  let parent = _____WB$wombat$assign$function_____("parent");
  let frames = _____WB$wombat$assign$function_____("frames");
  let opener = _____WB$wombat$assign$function_____("opener");

(self.webpackChunklite=self.webpackChunklite||[]).push([[8504],{19308:(e,n,t)=>{"use strict";t.d(n,{b:()=>a,I:()=>s});var i=t(319),r=t.n(i),l=t(68216),o=t(66081),a={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"CollectionFollowButton_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}}]}}]},s={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"CollectionFollowButton_collection"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Collection"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"slug"}},{kind:"FragmentSpread",name:{kind:"Name",value:"collectionUrl_collection"}},{kind:"FragmentSpread",name:{kind:"Name",value:"SusiClickable_collection"}}]}}].concat(r()(l.nf.definitions),r()(o.Os.definitions))}},31579:(e,n,t)=>{"use strict";t.d(n,{DI:()=>l,nj:()=>o});var i=t(319),r=t.n(i),l={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"useNewsletterV3Subscription_newsletterV3"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"NewsletterV3"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"type"}},{kind:"Field",name:{kind:"Name",value:"slug"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"collection"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"slug"}}]}},{kind:"Field",name:{kind:"Name",value:"user"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"username"}},{kind:"Field",name:{kind:"Name",value:"newsletterV3"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}}]}}]}}]},o={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"useNewsletterV3Subscription_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"username"}},{kind:"Field",name:{kind:"Name",value:"newsletterV3"},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"useNewsletterV3Subscription_newsletterV3"}}]}}]}}].concat(r()(l.definitions))};[{kind:"OperationDefinition",operation:"mutation",name:{kind:"Name",value:"fetchOrLazilyCreateNewsletterV3AndMaybeSubscribe"},variableDefinitions:[{kind:"VariableDefinition",variable:{kind:"Variable",name:{kind:"Name",value:"userId"}},type:{kind:"NonNullType",type:{kind:"NamedType",name:{kind:"Name",value:"ID"}}}}],selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"fetchOrLazilyCreateNewsletterV3AndMaybeSubscribe"},arguments:[{kind:"Argument",name:{kind:"Name",value:"userId"},value:{kind:"Variable",name:{kind:"Name",value:"userId"}}}],selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"FragmentSpread",name:{kind:"Name",value:"useNewsletterV3Subscription_newsletterV3"}}]}}]}}].concat(r()(l.definitions))},61279:(e,n,t)=>{"use strict";t.d(n,{oT:()=>D});var i=t(59713),r=t.n(i),l=t(63038),o=t.n(l),a=t(28655),s=t.n(a),u=t(82492),d=t.n(u),c=t(92471),m=t(21919),v=t(67294),b=t(25735),p=t(9354),f=t(75880),w=t(18627),S=t(66411),k=t(78285);function g(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);n&&(i=i.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,i)}return t}function h(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?g(Object(t),!0).forEach((function(n){r()(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):g(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function E(){var e=s()(["\n  mutation fetchOrLazilyCreateNewsletterV3AndMaybeSubscribe($userId: ID!) {\n    fetchOrLazilyCreateNewsletterV3AndMaybeSubscribe(userId: $userId) {\n      __typename\n      ...useNewsletterV3Subscription_newsletterV3\n    }\n  }\n  ","\n"]);return E=function(){return e},e}function y(){var e=s()(["\n  mutation unsubscribeNewsletterV3($newsletterV3Id: ID!) {\n    unsubscribeNewsletterV3(newsletterV3Id: $newsletterV3Id)\n  }\n"]);return y=function(){return e},e}function N(){var e=s()(["\n  mutation subscribeNewsletterV3($newsletterV3Id: ID!, $shouldRecordConsent: Boolean) {\n    subscribeNewsletterV3(\n      newsletterV3Id: $newsletterV3Id\n      shouldRecordConsent: $shouldRecordConsent\n    )\n  }\n"]);return N=function(){return e},e}function V(){var e=s()(["\n  fragment useNewsletterV3Subscription_newsletterV3_viewerEdge on NewsletterV3 {\n    viewerEdge {\n      id\n      isSubscribed\n    }\n  }\n"]);return V=function(){return e},e}function O(){var e=s()(["\n  fragment useNewsletterV3Subscription_user on User {\n    id\n    username\n    newsletterV3 {\n      ...useNewsletterV3Subscription_newsletterV3\n    }\n  }\n  ","\n"]);return O=function(){return e},e}function F(){var e=s()(["\n  fragment useNewsletterV3Subscription_newsletterV3 on NewsletterV3 {\n    id\n    type\n    slug\n    name\n    collection {\n      slug\n    }\n    user {\n      id\n      name\n      username\n      newsletterV3 {\n        id\n      }\n    }\n  }\n"]);return F=function(){return e},e}var C=(0,c.Ps)(F()),I=(0,c.Ps)(O(),C),P=((0,c.Ps)(V()),(0,c.Ps)(N())),_=(0,c.Ps)(y()),x=(0,c.Ps)(E(),C),D=function(e){var n=e.newsletterV3,t=e.creator,i=e.newsletterName,r=e.hideLinkInConfirmationToast,l=void 0!==r&&r,a=n||{},s=a.id,u=a.type,c=a.slug,g=a.collection,E=(null==n?void 0:n.user)||t,y=null!=i?i:null==n?void 0:n.name,N=v.useState(!1),V=o()(N,2),O=V[0],F=V[1],C=(0,p.T)({newsletterSlug:c,collectionSlug:null==g?void 0:g.slug,username:null==E?void 0:E.username}),D=C.viewerEdge,M=C.loading,T=(0,b.VB)({name:"enable_auto_follow_on_subscribe",placeholder:!1}),U=v.useState(!1),A=o()(U,2),R=A[0],j=A[1];v.useEffect((function(){j(!(null==D||!D.isSubscribed))}),[null==D?void 0:D.isSubscribed]);var B=(0,w.Av)(),L=(0,S.Qi)(),$=(0,k.w)();O&&B.event("newsletterV3.subscribe.error",{newsletterV3Id:s});var z=function(e,n,t){if(t){var i={id:"User:".concat(null==E?void 0:E.id),fragment:I,fragmentName:"useNewsletterV3Subscription_user"},r=e.readFragment(i);e.writeFragment(h(h({},i),{},{data:h(h({},r),{},{newsletterV3:t})}))}if(D){var l=e.readQuery({query:p.p,variables:{newsletterSlug:c,collectionSlug:null==g?void 0:g.slug,username:null==E?void 0:E.username}}),o=d()({},l,{newsletterV3:{viewerEdge:{isSubscribed:n}}});e.writeQuery({query:p.p,variables:{newsletterSlug:c||"",collectionSlug:null==g?void 0:g.slug,username:null==E?void 0:E.username},data:o})}n&&null!=E&&E.id&&T&&(0,f.I0)(e,E.id,{isFollowing:!0})},G=(0,m.D)(P,{onCompleted:function(e){var n=e.subscribeNewsletterV3;F(!n),n&&(B.event("newsletterV3.subscribeClicked",{newsletterV3Id:s,source:L}),j(!0))},update:function(e){z(e,!0)}}),W=o()(G,1)[0],H=(0,m.D)(_,{onCompleted:function(e){var n=e.unsubscribeNewsletterV3;F(!n),n&&(j(!1),$({duration:l?5e3:"NEXTPAGE",toastStyle:"NEWSLETTER_UNSUBSCRIBE",extraParams:{newsletterName:y||null,newsletterType:u||null,unsubscribeFn:function(){return j(!1)},hideEmailSettingsLink:l,hideCloseButton:l}}))},update:function(e){z(e,!1)}}),q=o()(H,1)[0],Q=(0,m.D)(x,{onCompleted:function(e){var n=e.fetchOrLazilyCreateNewsletterV3AndMaybeSubscribe;F(!n),n&&(B.event("newsletterV3.subscribeClicked",{newsletterV3Id:n.id,source:L}),j(!0))},update:function(e,n){var t,i=h({},null===(t=n.data)||void 0===t?void 0:t.fetchOrLazilyCreateNewsletterV3AndMaybeSubscribe);z(e,!0,i)}}),Y=o()(Q,1)[0];return{isSubscribed:R,hasError:O,setSubscribe:function(e){var i=arguments.length>1&&void 0!==arguments[1]&&arguments[1];F(!1),e&&!n&&null!=t&&t.id?Y({variables:{userId:null==t?void 0:t.id}}):e&&null!=n&&n.id?W({variables:{newsletterV3Id:null==n?void 0:n.id,shouldRecordConsent:i}}):null!=n&&n.id?q({variables:{newsletterV3Id:null==n?void 0:n.id}}):F(!0)},loading:M}}},67701:(e,n,t)=>{"use strict";t.d(n,{gY:()=>u});var i=t(28655),r=t.n(i),l=t(64718),o=t(92471);function a(){var e=r()(["\n  query CollectionViewerEdge($collectionId: ID!) {\n    collection(id: $collectionId) {\n      ... on Collection {\n        id\n        viewerEdge {\n          ...Collection_viewerEdge\n        }\n      }\n    }\n  }\n  ","\n"]);return a=function(){return e},e}function s(){var e=r()(["\n  fragment Collection_viewerEdge on CollectionViewerEdge {\n    id\n    canEditOwnPosts\n    canEditPosts\n    isEditor\n    isFollowing\n    isMuting\n    isSubscribedToLetters\n    isSubscribedToMediumNewsletter\n    isSubscribedToEmails\n    isWriter\n  }\n"]);return s=function(){return e},e}var u=function(e){var n,t,i=(0,l.a)(c,{variables:{collectionId:null!==(n=null==e?void 0:e.id)&&void 0!==n?n:""},ssr:!1,skip:!(null!=e&&e.id)}),r=i.loading,o=i.error,a=i.data;return r?{loading:r}:o?{error:o}:{viewerEdge:null==a||null===(t=a.collection)||void 0===t?void 0:t.viewerEdge}},d=(0,o.Ps)(s()),c=(0,o.Ps)(a(),d)},9354:(e,n,t)=>{"use strict";t.d(n,{T:()=>s,p:()=>u});var i=t(28655),r=t.n(i),l=t(64718),o=t(92471);function a(){var e=r()(["\n  query NewsletterV3ViewerEdge($newsletterSlug: ID!, $collectionSlug: ID, $username: ID) {\n    newsletterV3(\n      newsletterSlug: $newsletterSlug\n      collectionSlug: $collectionSlug\n      username: $username\n    ) {\n      ... on NewsletterV3 {\n        id\n        viewerEdge {\n          id\n          isSubscribed\n        }\n      }\n    }\n  }\n"]);return a=function(){return e},e}var s=function(e){var n,t=e.newsletterSlug,i=void 0===t?"":t,r=e.collectionSlug,o=e.username,a=(0,l.a)(u,{variables:{newsletterSlug:i,collectionSlug:r,username:o},ssr:!1,skip:!i&&!o}),s=a.loading,d=a.error,c=a.data;return s?{loading:s}:d?{error:d}:{viewerEdge:null==c||null===(n=c.newsletterV3)||void 0===n?void 0:n.viewerEdge}},u=(0,o.Ps)(a())},43822:(e,n,t)=>{"use strict";t.d(n,{a:()=>S});var i=t(28655),r=t.n(i),l=t(59713),o=t.n(l),a=t(92471),s=t(67294),u=t(27517),d=t(47230),c=t(93310),m=t(18627),v=t(66411),b=t(50458);function p(){var e=r()(["\n  fragment UpsellClickable_post on Post {\n    id\n    collection {\n      id\n    }\n    sequence {\n      sequenceId\n    }\n    creator {\n      id\n    }\n  }\n"]);return p=function(){return e},e}function f(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);n&&(i=i.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,i)}return t}function w(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?f(Object(t),!0).forEach((function(n){o()(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):f(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}(0,a.Ps)(p());var S=(0,u.$j)((function(e){return{authDomain:e.config.authDomain}}))((function(e){var n=e.authDomain,t=e.buttonSize,i=e.buttonStyle,r=e.children,l=e.eventData,o=void 0===l?{}:l,a=e.inline,u=void 0!==a&&a,p=e.isButton,f=void 0!==p&&p,S=e.linkStyle,k=void 0===S?"SUBTLE":S,g=e.post,h=e.redirectUrl,E=e.width,y=e.id,N=e.onClick,V=h||(0,b.OA)(n),O=(0,m.Av)(),F=(0,v.Lk)(),C=function(){var e,n;O.event("upsell.clicked",w(w({},o),{},{dimension:null==F?void 0:F.dimension,locationId:null==F?void 0:F.dimension,postId:null==g?void 0:g.id,authorId:null==g||null===(e=g.creator)||void 0===e?void 0:e.id,sequenceId:(null==g||null===(n=g.sequence)||void 0===n?void 0:n.sequenceId)||""}))};return f?s.createElement(d.z,{buttonStyle:i,href:V,onClick:function(){null==N||N(),C()},size:t,width:E,id:y},r):s.createElement(c.r,{onClick:function(){null==N||N(),C()},href:V,linkStyle:k,inline:u,id:y},r)}))},31711:(e,n,t)=>{"use strict";t.d(n,{N:()=>re});var i=t(63038),r=t.n(i),l=t(67294),o=t(32317),a=t(21919),s={kind:"Document",definitions:[{kind:"OperationDefinition",operation:"mutation",name:{kind:"Name",value:"UpdateUserPostSubscribeMembershipUpsellShownAt"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"userUpdatePostSubscribeMembershipUpsellShownAt"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"postSubscribeMembershipUpsellShownAt"}}]}}]}}]},u=t(6443),d=t(14818),c=t(13791),m=t(77355),v=t(54945),b=t(87691),p=t(18627),f=t(66411),w=t(43487),S=t(87498),k=t(78870),g=t(50458),h="after_subscribe_membership_upsell",E=function(e){var n=e.user,t=e.isVisible,i=e.hide,o=(0,w.v9)((function(e){return e.config.authDomain})),E=(0,p.Av)(),y=(0,u.H)(),N=y.value,V=y.loading;l.useEffect((function(){var e;V||null!=N&&N.postSubscribeMembershipUpsellShownAt||(E.event("newsletterV3.postSubscribeMembershipUpsellViewed",{newsletterV3Id:null===(e=n.newsletterV3)||void 0===e?void 0:e.id,source:h}),F())}),[V]);var O=(0,a.D)(s,{optimisticResponse:{userUpdatePostSubscribeMembershipUpsellShownAt:{__typename:"User",id:(null==N?void 0:N.id)||"",postSubscribeMembershipUpsellShownAt:(new Date).getTime()}}}),F=r()(O,1)[0];return l.createElement(f.cW,{source:{name:h}},l.createElement(c.v,{isVisible:t,hide:i,withCloseButton:!0,withAnimation:!0,buttonStyle:"STRONG",buttonSize:"REGULAR",cancelText:"Not now",confirmText:"Become a member",onConfirm:function(){var e,t;E.event("newsletterV3.postSubscribeMembershipUpsellClicked",{newsletterV3Id:null===(e=n.newsletterV3)||void 0===e?void 0:e.id,source:h}),t=(0,k.Rk)((0,g.c5)(o),{subscribeToUserId:n.id,source:h}),window.location.href=t},showCancelButton:!0,isDestructiveAction:!1},l.createElement(m.x,{marginBottom:"24px"},l.createElement(d.z,{miroId:n.imageId||S.gG,alt:n.name||"",diameter:80,freezeGifs:!1})),l.createElement(m.x,{marginBottom:{xs:"8px",sm:"8px",md:"16px",lg:"16px",xl:"16px"}},l.createElement(v.H2,{scale:{xs:"S",sm:"S",md:"L",lg:"L",xl:"L"}},"You’re subscribed to get email updates. Become a member for more.")),l.createElement(m.x,{marginBottom:"32px"},l.createElement(b.F,{tag:"span",scale:{xs:"M",sm:"M",md:"L",lg:"L",xl:"L"},color:"DARKER"},"Your membership fee directly supports ",n.name," and other writers you read. Get full access to every story on Medium."))))},y=t(77280),N=t(61279),V=t(93661),O=t(98863),F=t(26350),C=t(43822),I=t(47230),P=t(73917),_=t(26244),x=t(1383),D=t(14646),M=t(31889),T=t(34135),U=t(97217),A=t(78285);function R(){return(R=Object.assign||function(e){for(var n=1;n<arguments.length;n++){var t=arguments[n];for(var i in t)Object.prototype.hasOwnProperty.call(t,i)&&(e[i]=t[i])}return e}).apply(this,arguments)}var j=l.createElement("path",{d:"M14 7.29L15.6 9 18 6M11.62 7.04H7a1 1 0 0 0-1 1v7.13a1 1 0 0 0 1 1h8.54a1 1 0 0 0 1-1v-3.21"}),B=l.createElement("path",{d:"M6 8.44l5.27 3.87 1.4-1.06.7-.52"});const L=function(e){return l.createElement("svg",R({width:23,height:23,viewBox:"0 0 23 23",fill:"none"},e),j,B)};function $(){return($=Object.assign||function(e){for(var n=1;n<arguments.length;n++){var t=arguments[n];for(var i in t)Object.prototype.hasOwnProperty.call(t,i)&&(e[i]=t[i])}return e}).apply(this,arguments)}var z=l.createElement("path",{d:"M24 13l2 2 3-3.5M19.5 12.5h-7a1 1 0 0 0-1 1v11a1 1 0 0 0 1 1h13a1 1 0 0 0 1-1v-5"}),G=l.createElement("path",{d:"M11.5 14.5L19 20l4-3"});const W=function(e){return l.createElement("svg",$({width:38,height:38,viewBox:"0 0 38 38",fill:"none"},e),z,G)};function H(){return(H=Object.assign||function(e){for(var n=1;n<arguments.length;n++){var t=arguments[n];for(var i in t)Object.prototype.hasOwnProperty.call(t,i)&&(e[i]=t[i])}return e}).apply(this,arguments)}var q=l.createElement("path",{d:"M14.58 6.89h3.92M16.39 9V5.08M11.62 7.04H7a1 1 0 0 0-1 1v7.13a1 1 0 0 0 1 1h8.54a1 1 0 0 0 1-1v-3.21"}),Q=l.createElement("path",{d:"M6 8.44l5.27 3.87 2.81-2.11"});const Y=function(e){return l.createElement("svg",H({width:23,height:23,viewBox:"0 0 23 23",fill:"none"},e),q,Q)};function K(){return(K=Object.assign||function(e){for(var n=1;n<arguments.length;n++){var t=arguments[n];for(var i in t)Object.prototype.hasOwnProperty.call(t,i)&&(e[i]=t[i])}return e}).apply(this,arguments)}var J=l.createElement("rect",{x:26.25,y:9.25,width:.5,height:6.5,rx:.25}),X=l.createElement("rect",{x:29.75,y:12.25,width:.5,height:6.5,rx:.25,transform:"rotate(90 29.75 12.25)"}),Z=l.createElement("path",{d:"M19.5 12.5h-7a1 1 0 0 0-1 1v11a1 1 0 0 0 1 1h13a1 1 0 0 0 1-1v-5"}),ee=l.createElement("path",{d:"M11.5 14.5L19 20l4-3"});const ne=function(e){return l.createElement("svg",K({width:38,height:38,viewBox:"0 0 38 38",fill:"none"},e),J,X,Z,ee)};var te=t(68894),ie=function(e){var n=e.user,t=e.showMembershipUpsellModal,i=void 0!==t&&t,o=e.showPostFollowSubscribeTooltip,a=void 0!==o&&o,s=e.hidePostFollowSubscribeTooltip,d=e.isVisible,c=void 0===d||d,v=e.isCompact,S=void 0!==v&&v,h=e.buttonStyleFn,R=void 0===h?function(e){return e?"OBVIOUS":"STRONG"}:h,j=l.useRef(null),B=(0,D.I)(),$=(0,M.F)(),z=(0,u.H)().value,G=(0,te.O)(!1),H=r()(G,3),q=H[0],Q=H[1],K=H[2],J=n.newsletterV3,X=(0,A.w)(),Z=(0,p.Av)(),ee=(0,f.pK)(),ie=(0,f.Qi)(),re=(0,y.PM)(),le=(0,N.oT)({newsletterV3:J,creator:n,newsletterName:n.name||void 0}),oe=le.isSubscribed,ae=le.hasError,se=le.loading,ue=le.setSubscribe,de=(0,w.v9)((function(e){return e.config.authDomain})),ce=(0,k.Rk)((0,g.c5)(de),{subscribeToUserId:n.id,source:ie}),me=!(null==z||!z.mediumMemberAt),ve=l.useState(!1),be=r()(ve,2),pe=be[0],fe=be[1],we=l.useState(!1),Se=r()(we,2),ke=Se[0],ge=Se[1],he=(0,f.P7)(re||"").susiEntry,Ee=void 0===he?"":he,ye=["newsletter_v3_promo","writer_subscription_landing"].includes(Ee),Ne=["newsletter_v3_promo"].includes(Ee),Ve=(0,V.OS)({membershipType:V.FM.Monthly}),Oe=!1,Fe=function(){var e;!Oe&&c&&Ce()&&(Z.event("newsletterV3.subscribePresented",{newsletterV3Id:(null===(e=n.newsletterV3)||void 0===e?void 0:e.id)||"",source:ee}),Oe=!0)},Ce=function(){var e;if(!j.current)return!1;var n=null===(e=j.current)||void 0===e?void 0:e.getBoundingClientRect(),t=n.top+n.height/2;return t>=0&&t<=window.innerHeight};l.useEffect((function(){return Fe(),window&&T.V6.on("scroll",Fe),function(){T.V6.off("scroll",Fe)}}),[]),l.useEffect((function(){Fe()}),[c]);var Ie=(0,te.O)(!1),Pe=r()(Ie,3),_e=Pe[0],xe=Pe[1],De=Pe[2],Me=function(e,n){var t=(0,u.H)(),i=t.value,r=t.loading,o=l.useRef(null),a=!(null==i||!i.mediumMemberAt),s=(0,y.PM)(),d=(0,f.P7)(s||"").susiEntry,c=["newsletter_v3_promo","writer_subscription_landing","subscribe_user"].includes(void 0===d?"":d);if(r)return!1;if(null!==o.current)return o.current;var m=c&&!a&&!e.viewerEdge.isUser&&!!e.isPartnerProgramEnrolled&&!(null!=i&&i.postSubscribeMembershipUpsellShownAt);return o.current=m,m}(n),Te=l.useState(!1),Ue=r()(Te,2),Ae=Ue[0],Re=Ue[1];l.useEffect((function(){i&&oe&&!Ae&&Me?xe():De()}),[oe,Ae,Me]),l.useEffect((function(){re&&!Me&&ye&&oe&&(!Ne&&ie===Ee||Ne)&&X({duration:"NEXTPAGE",toastStyle:"NEWSLETTER_SUBSCRIBE",extraParams:{newsletterName:n.name,newsletterType:U.Rr.NEWSLETTER_TYPE_AUTHOR,unsubscribeFn:function(){return ue(!1)}}})}),[re,oe]),l.useEffect((function(){if(oe&&ke&&J){var e=!me&&!!n.isPartnerProgramEnrolled;e&&Z.event("newsletterV3.postSubscribeMembershipUpsellViewed",{newsletterV3Id:J.id,source:ie}),fe(e),ge(!1)}}),[oe,ke,J]);var je=(0,O.f)().isWorkingPreview;if(ae||n.viewerEdge.isUser&&!je)return null;var Be,Le=R(!!oe),$e=function(e,n){return function(t){return{stroke:n?t.baseColor.background.normal:e,height:S?"23px":"36px",width:S?"23px":"36px"}}},ze=B($e("OBVIOUS"===Le?$.accentColor.fill.normal:$.baseColor.fill.dark,se)),Ge=B($e("STRONG"===Le?$.accentColor.background:$.backgroundColor,se));Be=oe?S?l.createElement(L,{className:ze}):l.createElement(W,{className:ze}):S?l.createElement(Y,{className:Ge}):l.createElement(ne,{className:Ge});var We=l.createElement(I.z,{loading:se,buttonStyle:Le,onClick:function(){var e;ge(!oe),z?oe?ue(!1):z&&z.allowEmailAddressSharingEditorWriter?ue(!0,!1):Q():null!==(e=n.newsletterV3)&&void 0!==e&&e.id?Z.event("newsletterV3.subscribeClicked",{newsletterV3Id:n.newsletterV3.id,source:ie}):Z.event("user.LOSubscribeClicked",{targetUserId:n.id,source:ie})},padding:"0","aria-label":"Subscribe"},Be),He=function(){return l.createElement(m.x,{padding:"14px 12px 20px",maxWidth:"220px"},l.createElement(b.F,{tag:"div",scale:"S",color:"DARKER"},l.createElement("strong",null,"You're subscribed to ",n.name,". Become a member for more.")," Get full access to every story on Medium for ",Ve," a month."),l.createElement(m.x,{paddingTop:"8px"},l.createElement(C.a,{isButton:!0,buttonStyle:"STRONG",buttonSize:"SMALL",redirectUrl:ce,width:"150px",onClick:function(){Z.event("newsletterV3.postSubscribeMembershipUpsellClicked",{newsletterV3Id:J.id,source:ie})}},l.createElement(m.x,{textAlign:"center"},l.createElement(b.F,{scale:"S",color:"WHITE"},"Become a member")))))},qe=function(){return l.createElement(m.x,{padding:"10px 12px",maxWidth:"166px"},l.createElement(b.F,{tag:"div",scale:"S",color:"DARKER"},"Subscribe to get an email whenever ",n.name," publishes."))},Qe=function(e){var n=e.children;return l.createElement(P.J,{isVisible:!!s&&!oe,hide:s,placement:"bottom",popoverRenderFn:qe,targetDistance:10,role:"tooltip"},n)},Ye=function(e){var n=e.children;return l.createElement(P.J,{isVisible:!se&&pe,hide:function(){return fe(!1)},placement:"bottom",popoverRenderFn:He,targetDistance:10,role:"tooltip"},n)},Ke=function(e){var n=e.children;return l.createElement(_.$,{isVisible:!se&&!oe,hideOnClick:!0,noPortal:!0,mouseEnterDelay:500,mouseLeaveDelay:0,placement:"bottom",popoverRenderFn:qe,role:"tooltip",targetDistance:10},n)},Je=function(e){var n=e.children;return a&&!oe?l.createElement(Qe,null,n):pe?l.createElement(Ye,null,n):l.createElement(Ke,null,n)};return l.createElement("div",{ref:j},l.createElement(Je,null,l.createElement(m.x,null,z&&l.createElement(x.Q,{onConfirm:function(){ue(!0,!0)},isVisible:q,hide:K,titleText:"Confirm your subscription to ".concat(n.name),confirmText:"Confirm now",buttonStyle:"STRONG",buttonSize:"LARGE",showCancelButton:!1,withCloseButton:!1,isDestructiveAction:!1},"When you subscribe to a writer or publication, your email address will be shared with them so they can stay in contact with you outside of Medium. Opt out any time by unsubscribing in Settings."),z?We:l.createElement(F.R,{operation:"register",newsletterV3:J,user:n,actionUrl:J?(0,g.Zu)(J.id):(0,g.lc)(n.id),susiEntry:"subscribe_user"},We))),_e&&l.createElement(E,{user:n,isVisible:_e,hide:function(){Re(!0),De()}}))},re=function(e){var n=e.creator,t=e.followButtonSize,i=void 0===t?"REGULAR":t,a=e.shouldHideTooltip,s=void 0!==a&&a,u=e.post,d=e.showMembershipUpsellModal,c=e.susiEntry,v=e.isVisible,b=e.width,p=e.isSubscribeCompact,f=void 0!==p&&p,w=e.buttonStyleFn,S=l.useState(!1),k=r()(S,2),g=k[0],h=k[1];return l.createElement(l.Fragment,null,l.createElement(o.B,{buttonSize:i,onClick:function(){n.viewerEdge.isFollowing||h(!0)},post:u,user:n,susiEntry:c,width:b,buttonStyleFn:w}),l.createElement(m.x,{marginLeft:f?"4px":"8px"},l.createElement(ie,{user:n,showMembershipUpsellModal:d,showPostFollowSubscribeTooltip:g&&!s,hidePostFollowSubscribeTooltip:function(){return h(!1)},isVisible:v,isCompact:f,buttonStyleFn:w})))}},27048:(e,n,t)=>{"use strict";t.d(n,{W:()=>o});var i=t(319),r=t.n(i),l=t(68216),o={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"UserAvatar_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"imageId"}},{kind:"Field",name:{kind:"Name",value:"mediumMemberAt"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"username"}},{kind:"FragmentSpread",name:{kind:"Name",value:"userUrl_user"}}]}}].concat(r()(l.$m.definitions))}}}]);
//# sourceMappingURL=https://stats.medium.build/lite/sourcemaps/8504.38fe30b1.chunk.js.map

}
/*
     FILE ARCHIVED ON 10:34:19 May 19, 2023 AND RETRIEVED FROM THE
     INTERNET ARCHIVE ON 10:16:15 May 16, 2024.
     JAVASCRIPT APPENDED BY WAYBACK MACHINE, COPYRIGHT INTERNET ARCHIVE.

     ALL OTHER CONTENT MAY ALSO BE PROTECTED BY COPYRIGHT (17 U.S.C.
     SECTION 108(a)(3)).
*/
/*
playback timings (ms):
  captures_list: 0.603
  exclusion.robots: 0.083
  exclusion.robots.policy: 0.074
  esindex: 0.011
  cdx.remote: 15.469
  LoadShardBlock: 168.972 (3)
  PetaboxLoader3.datanode: 67.945 (5)
  PetaboxLoader3.resolve: 115.731 (2)
  load_resource: 20.85 (2)
*/