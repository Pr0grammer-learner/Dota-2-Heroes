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

(self.webpackChunklite=self.webpackChunklite||[]).push([[8745],{32931:(e,n,i)=>{"use strict";i.d(n,{j:()=>h});var t=i(63038),a=i.n(t),o=i(67154),d=i.n(o),l=i(6479),r=i.n(l),m=i(18446),s=i.n(m),c=i(67294),u=i(18733),k=i(77355),p=i(21755),v=i(31889),f=i(14646),S=i(77241),g=i(17583),N=i(6280),y=function(e){return{position:"sticky",opacity:e?1:0,visibility:e?"visibile":"hidden",display:"flex",justifyContent:"center",transition:"opacity 300ms",zIndex:S.ZP.selectionMenu}},F={bottom:"16px"},_=function(e,n){return function(i){return{bottom:e?"0":"16px","> div":{transform:"translateY(".concat(n,"px)"),borderTop:e?"solid 1px ".concat(i.baseColor.background.normal):void 0}}}},C=function(e){var n=e.margin,i=void 0===n?"0 16px":n;return c.createElement(k.x,{margin:i,height:"12px",borderRight:"BASE_LIGHTER"})},R=function(e){var n=e.isSingleColumn,i=r()(e,["isSingleColumn"]);return c.createElement(k.x,d()({display:"flex",flexBasis:n?"0":void 0,flexGrow:n?"1":void 0,flexShrink:n?"1":void 0,justifyContent:n?"center":void 0,alignItems:"center"},i))},b=(0,c.memo)((function(e){var n=e.multiVoteButton,i=e.responsesButton,t=e.saveButton,a=e.allowResponses,o=e.isSingleColumn,d=a||o,l=(0,v.F)(),r=(0,u.Uo)().baseTheme,m=(0,c.useMemo)((function(){return l.backgroundColor!==r.backgroundColor||!s()(l.baseColor.background,r.baseColor.background)}),[l,r]);return c.createElement(k.x,{width:o?"100%":void 0,justifyContent:o?"stretch":void 0,display:"flex",backgroundColor:"BACKGROUND",alignItems:"center",borderRadius:o?"0":"20px",border:m&&!o?"BASE_LIGHTER":"NONE",padding:o?"0":"0 14px 0 16px",height:o?"48px":"40px",boxShadow:o?void 0:"0px 2px 10px 0px rgba(0, 0, 0, 0.1)"},c.createElement(R,{isSingleColumn:o},n),d&&c.createElement(R,{isSingleColumn:o},!o&&c.createElement(C,null),i),t&&c.createElement(c.Fragment,null,!o&&c.createElement(C,{margin:"0 12px 0 16px"}),c.createElement(R,{isSingleColumn:o},t)))})),w=function(e){var n=e.children,i=(0,f.I)(),t=(0,N.$)(!0),a=t.dockRef,o=t.markerRef,d=t.isStuck;return c.createElement(c.Fragment,null,c.createElement("div",{ref:o}),c.createElement("div",{ref:a,className:i([y(d),F])},n))},E=function(e){var n=e.children,i=e.isSingleColumn,t=(0,f.I)(),o=(0,c.useRef)(),d=(0,c.useState)(0),l=a()(d,2),r=l[0],m=l[1],s=(0,c.useCallback)((function(e){m((function(n){return Math.max(Math.min(n+e,56),0)}))}),[m]),u=(0,c.useCallback)((function(){var e,n=null===(e=v.current)||void 0===e?void 0:e.getBoundingClientRect().y;window.scrollY>0&&o.current&&n&&s(o.current-n),o.current=n}),[s]),k=(0,N.$)(!0,u),p=k.dockRef,v=k.markerRef,S=k.isStuck;return c.createElement(c.Fragment,null,c.createElement("div",{ref:v}),c.createElement("div",{ref:p,className:t([y(S),_(i,r)])},n))},h=function(e){var n=e.isSingleColumn,i=(0,g.s)(),t=(0,c.useMemo)((function(){return!(n||i&&i!==p.j.xl)}),[i,n]),a=(0,c.useMemo)((function(){return n?i===p.j.xs||i===p.j.sm:i!==p.j.xl}),[i,n]);return t?c.createElement(w,null,c.createElement(b,e)):a?c.createElement(E,{isSingleColumn:!!n},c.createElement(b,d()({isSingleColumn:n},e))):null}},6280:(e,n,i)=>{"use strict";i.d(n,{$:()=>l});var t=i(63038),a=i.n(t),o=i(67294),d=i(34135),l=function(e,n){var i=(0,o.useRef)(null),t=(0,o.useRef)(null),l=(0,o.useState)(!0),r=a()(l,2),m=r[0],s=r[1];return(0,o.useEffect)((function(){var a=function(){var e,a,o=null===(e=i.current)||void 0===e?void 0:e.getBoundingClientRect().y,d=null===(a=t.current)||void 0===a?void 0:a.getBoundingClientRect().y;o&&d&&s(Boolean(d-o)),null==n||n()};if(a(),e)return d.V6.on("scroll",a),function(){d.V6.off("scroll",a)}}),[e]),{isStuck:e&&m,dockRef:i,markerRef:t}}},60672:(e,n,i)=>{"use strict";i.d(n,{e:()=>u});var t=i(67294),a=i(27517),o=i(18702),d=i(25550),l=i(6443),r=i(98067),m=i(77280),s=i(43487),c=i(55765),u=function(e){var n=e.data,i=void 0===n?{}:n,u=e.isBlocked,k=void 0!==u&&u,p=e.loading,v=e.show,f=i.canonicalUrl,S=i.collectionViewerEdge,g=i.creatorViewerEdge,N=i.meteringInfo,y=i.pageType,F=i.post,_=i.profileName,C=i.profilePhoto,R=i.profileUsername,b=i.topicViewerEdge,w=(0,a.I0)(),E=(0,d.r)(),h=E.loading,D=E.viewerId,P=(0,c.P)(),T=P.loading,I=P.inAppBrowser,x=(0,l.H)(),B=x.loading,O=x.value,U=(0,s.v9)((function(e){return e.navigation.referrer})),M=(0,m.PM)();(0,t.useEffect)((function(){if(!(p||B||h||!D||T)){var e=(0,o.RD)({collectionViewerEdge:S,creatorViewerEdge:g,currentUserId:D,inAppBrowser:I,meteringInfo:N,page_type:y,post:F,profile_name:_,profile_photo:C,profile_username:R,referrer:U,referrerSource:M,viewer:O,topicViewerEdge:b});return f&&(e.data.$canonical_url=f),(0,o.Pu)(e),w((0,r.aj)(e)),v&&(w((0,r.QZ)()),w((0,r.Dl)(k))),function(){w((0,r.Uo)())}}}),[p,B,h,D,T])}},82405:(e,n,i)=>{"use strict";i.d(n,{F:()=>C});var t=i(63038),a=i.n(t),o=i(21919),d=i(67294),l=i(5977),r=i(77520),m=i(20297),s=i(25550),c=i(25267),u=i(67701),k=i(26350),p=i(50563),v=i(93310),f=i(77355),S=i(47230),g=i(18627),N=i(66411),y=i(92661),F=i(43487),_=i(50458),C=function(e){var n,i=e.buttonSize,t=e.buttonStyleFn,_=e.collection,C=e.post,b=e.simpleLink,w=e.susiEntry,E=void 0===w?"follow_card":w,h=e.preventParentClick,D=(0,F.v9)((function(e){return e.config.authDomain})),P=(0,s.r)().viewerId,T=(0,g.Av)(),I=(0,N.pK)(),x=(0,l.TH)(),B=(0,y.$B)(x.pathname),O=null==B||null===(n=B.route)||void 0===n?void 0:n.name,U=(0,u.gY)(_),M=U.viewerEdge,H=U.loading,j=function(e,n){var i=(0,o.D)(m.e),t=a()(i,1)[0];return d.useCallback((function(){return t({variables:{id:e.id},optimisticResponse:{followCollection:{__typename:"Collection",id:e.id,name:e.name,viewerEdge:{__typename:"CollectionViewerEdge",id:"collectionId:".concat(e.id,"-viewerId:").concat(n),isFollowing:!0}}},update:function(i){i.modify({id:"User:".concat(n),fields:{missionControl:(0,p.im)("followedCollections",!0),followingCollectionConnection:(0,p.Hc)(e.id)}})}})}),[e.id])}(_,P),V=function(e,n){var i=(0,o.D)(m.X),t=a()(i,1)[0];return d.useCallback((function(){return t({variables:{id:e.id},optimisticResponse:{unfollowCollection:{__typename:"Collection",id:e.id,name:e.name,viewerEdge:{__typename:"CollectionViewerEdge",id:"collectionId:".concat(e.id,"-viewerId:").concat(n),isFollowing:!1}}},update:function(e){e.modify({id:"User:".concat(n),fields:{missionControl:(0,p.im)("followedCollections",!1)}})}})}),[e.id])}(_,P),A=d.useCallback((function(e){h&&e.preventDefault(),T.event("collection.followed",{collectionId:_.id,followSource:I}),j()}),[_,h,I,T]),W=d.useCallback((function(e){h&&e.preventDefault(),T.event("collection.unfollowed",{collectionId:_.id,followSource:I}),V()}),[h,I,T]),L=!(null==M||!M.isFollowing),z=t?t(!!L):L?"OBVIOUS":"STRONG";return b?d.createElement(v.r,{onClick:L?W:A},d.createElement(f.x,{display:"flex",flexDirection:"row"},L?"Unfollow publication":"Follow publication")):d.createElement(c.I,null,(function(e){return e?d.createElement(S.z,{size:i,onClick:L?W:A,buttonStyle:z,loading:H},L?"Following":"Follow"):d.createElement(k.R,{collection:_,buttonStyle:L?"OBVIOUS":"STRONG",isButton:!0,buttonSize:"REGULAR",operation:"register",actionUrl:R(D,_,C)||"",susiEntry:E,pageSource:(0,r.x)(O,"register")},L?"Following":"Follow")}))},R=function(e,n,i){return n.slug&&(i&&i.id?(0,_.TA)(e,n.slug,i.id):(0,_.Ll)(e,n.slug))}},20512:(e,n,i)=>{"use strict";i.d(n,{Y4:()=>l,NJ:()=>r,lc:()=>m});var t=i(59713),a=i.n(t),o=i(46696);function d(e,n){var i=Object.keys(e);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(e);n&&(t=t.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),i.push.apply(i,t)}return i}function l(e){var n=e.miroId,i=e.originalWidth,t=e.originalHeight,a=e.focusPercentX,d=e.focusPercentY,l=e.croppedWidth;if(!n)return null;var r=(0,o.vz)({miroId:n,aspectRatio:16/9,croppedWidth:l,originalWidth:i,originalHeight:t,focusPercentX:a,focusPercentY:d}),m=(0,o.vz)({miroId:n,aspectRatio:4/3,croppedWidth:l,originalWidth:i,originalHeight:t,focusPercentX:a,focusPercentY:d}),s=(0,o.vz)({miroId:n,aspectRatio:1,croppedWidth:l,originalWidth:i,originalHeight:t,focusPercentX:a,focusPercentY:d}),c=new Set([r,m,s]);return Array.from(c)}function r(e){return function(e){for(var n=1;n<arguments.length;n++){var i=null!=arguments[n]?arguments[n]:{};n%2?d(Object(i),!0).forEach((function(n){a()(e,n,i[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(i)):d(Object(i)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(i,n))}))}return e}({"@type":"ImageObject"},e)}function m(e){var n=e.id,i=e.originalWidth,t=e.originalHeight;if(!n||!i||!t)return null;var a=Math.min(t,60),d=a/t,l=Math.floor(i*d);return r({width:l,height:a,url:(0,o.W6)({miroId:n,width:l,freezeGifs:!0,strategy:o._S.Resample})})}},81712:(e,n,i)=>{"use strict";i.d(n,{f:()=>l});var t=i(319),a=i.n(t),o=i(19308),d=i(78693),l={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PublisherFollowButton_publisher"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Publisher"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"InlineFragment",typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Collection"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"CollectionFollowButton_collection"}}]}},{kind:"InlineFragment",typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"UserFollowButton_user"}}]}}]}}].concat(a()(o.I.definitions),a()(d.s.definitions))}},12182:(e,n,i)=>{"use strict";i.d(n,{fu:()=>_,e9:()=>y});var t=i(319),a=i.n(t),o=i(18821),d=i(66081),l={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ReportUserMenuItem_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"SusiClickable_post"}}]}}].concat(a()(d.qU.definitions))},r={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ResponsePopoverMenu_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ReportUserMenuItem_post"}},{kind:"FragmentSpread",name:{kind:"Name",value:"HideResponseMenuItem_post"}},{kind:"FragmentSpread",name:{kind:"Name",value:"BlockUserMenuItem_post"}}]}}].concat(a()(l.definitions),a()([{kind:"FragmentDefinition",name:{kind:"Name",value:"HideResponseMenuItem_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"collection"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"viewerEdge"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"isEditor"}}]}}]}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}}]}}]),a()([{kind:"FragmentDefinition",name:{kind:"Name",value:"BlockUserMenuItem_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}}]}}]))},m={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ResponsePopoverMenu_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ReportUserMenuItem_catalog"}},{kind:"FragmentSpread",name:{kind:"Name",value:"HideResponseMenuItem_catalog"}},{kind:"FragmentSpread",name:{kind:"Name",value:"BlockUserMenuItem_catalog"}}]}}].concat(a()([{kind:"FragmentDefinition",name:{kind:"Name",value:"ReportUserMenuItem_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}}]}}]),a()([{kind:"FragmentDefinition",name:{kind:"Name",value:"HideResponseMenuItem_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}}]}}]),a()([{kind:"FragmentDefinition",name:{kind:"Name",value:"BlockUserMenuItem_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}}]}}]))},s={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ResponseHeader_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"useIsVerifiedBookAuthor_user"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"ResponsePopoverMenu_post"}}]}}].concat(a()(o.H.definitions),a()(r.definitions))},c={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ResponseHeader_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"useIsVerifiedBookAuthor_user"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"ResponsePopoverMenu_catalog"}}]}}].concat(a()(o.H.definitions),a()(m.definitions))},u={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"SimpleResponse_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ResponseHeader_post"}}]}}].concat(a()(s.definitions))},k={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"SimpleResponse_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ResponseHeader_catalog"}}]}}].concat(a()(c.definitions))},p=i(13740),v={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ReadOrEditSimpleResponse_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"SimpleResponse_post"}}]}}].concat(a()(u.definitions))},f={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ReadOrEditSimpleResponse_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"username"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"SimpleResponse_catalog"}},{kind:"FragmentSpread",name:{kind:"Name",value:"getCatalogSlugId_Catalog"}}]}}].concat(a()(k.definitions),a()(p.g.definitions))},S={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"StoryResponse_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ResponseHeader_post"}}]}}].concat(a()(s.definitions))},g={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"StoryResponse_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ResponseHeader_catalog"}}]}}].concat(a()(c.definitions))},N={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ThreadedReply_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ReadOrEditSimpleResponse_post"}},{kind:"FragmentSpread",name:{kind:"Name",value:"StoryResponse_post"}}]}}].concat(a()(v.definitions),a()(S.definitions))},y={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ThreadedReplies_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ThreadedReply_post"}}]}}].concat(a()(N.definitions))},F={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ThreadedReply_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ReadOrEditSimpleResponse_catalog"}},{kind:"FragmentSpread",name:{kind:"Name",value:"StoryResponse_catalog"}}]}}].concat(a()(f.definitions),a()(g.definitions))},_={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ThreadedReplies_catalog"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Catalog"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ThreadedReply_catalog"}}]}}].concat(a()(F.definitions))}},43242:(e,n,i)=>{"use strict";i.d(n,{E:()=>p});var t=i(319),a=i.n(t),o=i(63038),d=i.n(o),l=i(38125),r=i.n(l),m=i(67294),s=i(21232),c=i(31889),u=i(34135),k=i(77280),p=function(e){var n=e.children,i=m.useState(!1),t=d()(i,2),o=t[0],l=t[1],p=(0,c.F)(),v=!!(0,k.Wd)("responsesOpen"),f=(0,k.Wd)("sortBy"),S=m.useState(!1),g=d()(S,2),N=g[0],y=g[1],F=m.useRef(!0),_=m.useRef(0),C=m.useState(!1),R=d()(C,2),b=R[0],w=R[1],E=m.useCallback((function(){return y(!0)}),[]),h=m.useState([]),D=d()(h,2),P=D[0],T=D[1],I=m.useCallback((function(e){F.current=!1,T([].concat(a()(P),[e]))}),[P]),x=m.useCallback((function(){T(r()(P))}),[P]),B=m.useCallback((function(){y(!1),T([]),F.current=!0}),[]);m.useEffect((function(){w(!0),y(v)}),[v]);var O=function(){window.innerWidth<p.breakpoints.md&&l(!0)};return m.useEffect((function(){return O(),u.V6.on("resize",O),function(){return u.V6.off("resize",O)}}),[]),m.useEffect((function(){var e,n,i=null===(e=window)||void 0===e||null===(n=e.document)||void 0===n?void 0:n.documentElement;return o&&null!=i&&i.style&&(N?(i.style.top="-".concat(_.current,"px"),_.current=i.scrollTop,i.style.overflow="hidden",i.style.position="fixed"):(i.style.overflow="",i.style.position="",i.style.top="",i.scrollTop=_.current)),function(){o&&null!=i&&i.style&&(i.style.overflow="",i.style.position="",i.style.top="",i.scrollTop=_.current)}}),[N]),m.createElement(s.f.Provider,{value:{addContinueThisThreadSidebar:I,openSidebar:E,closeSidebar:B}},n({showPreviousSidebar:x,hasLoaded:b,initialSidebarRender:F,isVisible:N,continueThisThreadPosts:P,openSidebar:E,cleanupSidebar:B,responseSortOption:f}))}},55193:(e,n,i)=>{"use strict";i.d(n,{v:()=>t,Q:()=>a});var t={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"SuspendedBannerLoader_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"isSuspended"}}]}}]},a={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"SuspendedBannerLoader_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"isSuspended"}}]}}]}},66018:(e,n,i)=>{"use strict";i.d(n,{Lv:()=>u});var t=i(28655),a=i.n(t),o=i(92471),d=i(67294),l=i(27517),r=i(25735),m=i(78285);function s(){var e=a()(["\n  fragment SuspendedBannerLoader_post on Post {\n    id\n    isSuspended\n  }\n"]);return s=function(){return e},e}function c(){var e=a()(["\n  fragment SuspendedBannerLoader_user on User {\n    id\n    isSuspended\n  }\n"]);return c=function(){return e},e}var u=function(e){var n=e.user,i=e.post,t=e.forceLoad,a=void 0!==t&&t,o=(0,l.I0)(),s=(0,r.VB)({name:"can_view_suspended_content",placeholder:!1})||a;return d.useEffect((function(){s&&(n&&n.isSuspended?o((0,m.Dx)({duration:"NEXTPAGE",toastStyle:"USER_SUSPENDED"})):i&&i.isSuspended&&o((0,m.Dx)({duration:"NEXTPAGE",toastStyle:"POST_SUSPENDED",extraParams:{postId:(null==i?void 0:i.id)||""}})))}),[s]),null};(0,o.Ps)(c()),(0,o.Ps)(s())}}]);
//# sourceMappingURL=https://stats.medium.build/lite/sourcemaps/8745.f6f45c8e.chunk.js.map

}
/*
     FILE ARCHIVED ON 10:34:19 May 19, 2023 AND RETRIEVED FROM THE
     INTERNET ARCHIVE ON 10:16:33 May 16, 2024.
     JAVASCRIPT APPENDED BY WAYBACK MACHINE, COPYRIGHT INTERNET ARCHIVE.

     ALL OTHER CONTENT MAY ALSO BE PROTECTED BY COPYRIGHT (17 U.S.C.
     SECTION 108(a)(3)).
*/
/*
playback timings (ms):
  captures_list: 0.829
  exclusion.robots: 0.094
  exclusion.robots.policy: 0.082
  esindex: 0.012
  cdx.remote: 7.818
  LoadShardBlock: 287.165 (3)
  PetaboxLoader3.resolve: 288.512 (5)
  PetaboxLoader3.datanode: 87.043 (5)
  load_resource: 111.756 (2)
*/