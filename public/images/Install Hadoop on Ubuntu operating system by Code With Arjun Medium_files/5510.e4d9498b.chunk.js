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

(self.webpackChunklite=self.webpackChunklite||[]).push([[5510],{4088:(e,n,i)=>{"use strict";i.d(n,{u:()=>o});var t=i(319),a=i.n(t),l=i(68216),o={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"usePostUrl_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"userUrl_user"}}]}},{kind:"Field",name:{kind:"Name",value:"collection"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"domain"}},{kind:"Field",name:{kind:"Name",value:"slug"}}]}},{kind:"Field",name:{kind:"Name",value:"isSeries"}},{kind:"Field",name:{kind:"Name",value:"mediumUrl"}},{kind:"Field",name:{kind:"Name",value:"sequence"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"slug"}}]}},{kind:"Field",name:{kind:"Name",value:"uniqueSlug"}}]}}].concat(a()(l.$m.definitions))}},60765:(e,n,i)=>{"use strict";i.d(n,{g:()=>l});var t=i(67294),a=i(27323),l=function(e){var n=e.children,i=e.className,l=void 0===i?"":i,o=e.href,d=e.onClick;return o?t.createElement(a.P,{className:l,href:o,onClick:d},n):n}},62549:(e,n,i)=>{"use strict";i.d(n,{t:()=>a});var t=i(319),a={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"DraftStatus_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"pendingCollection"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"BoldCollectionName_collection"}}]}},{kind:"Field",name:{kind:"Name",value:"statusForCollection"}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}},{kind:"Field",name:{kind:"Name",value:"isPublished"}}]}}].concat(i.n(t)()([{kind:"FragmentDefinition",name:{kind:"Name",value:"BoldCollectionName_collection"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Collection"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}}]}}]))}},50455:(e,n,i)=>{"use strict";i.d(n,{e:()=>E});var t=i(28655),a=i.n(t),l=i(92471),o=i(67294),d=i(70929),r=i(84130),s=i(62212),c=i(6443),m=i(26350),u=i(66081),k=i(30020),v=i(14646),p=i(97217),f=i(43487),S=i(353),N=i(50458);function F(){var e=a()(["\n  fragment BookmarkButton_post on Post {\n    visibility\n    ...SusiClickable_post\n    ...AddToCatalogBookmarkButton_post\n  }\n  ","\n  ","\n"]);return F=function(){return e},e}function E(e){var n=e.post,i=e.withReadingListTooltip,t=void 0===i||i,a=e.susiEntry,l=e.rules,r=e.targetDistance,u=void 0===r?10:r,F=n.id,E=n.visibility,C=(0,v.I)(),g=(0,f.v9)((function(e){return e.config.authDomain})),h=(0,c.H)(),y=h.value;return h.loading||E===p.Wn.UNLISTED?null:y?o.createElement(d.o,{kind:p.ej.POST,target:n,rules:l}):o.createElement(k._,{isVisible:t,placement:"top",targetDistance:u,tooltipText:"Bookmark story"},o.createElement(m.R,{post:n,operation:"register",actionUrl:(0,N.XE)(g,F),susiEntry:a},o.createElement(S.Z,{className:C([s.K,l])})))}(0,l.Ps)(F(),u.qU,r.G)},8994:(e,n,i)=>{"use strict";i.d(n,{Z:()=>d,A:()=>r});var t=i(319),a=i.n(t),l=i(68216),o=i(18821),d={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ExpandablePostByline_collection"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Collection"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"domain"}},{kind:"Field",name:{kind:"Name",value:"slug"}}]}}]},r={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ExpandablePostByline_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"imageId"}},{kind:"FragmentSpread",name:{kind:"Name",value:"userUrl_user"}},{kind:"FragmentSpread",name:{kind:"Name",value:"useIsVerifiedBookAuthor_user"}}]}}].concat(a()(l.$m.definitions),a()(o.H.definitions))}},36579:(e,n,i)=>{"use strict";i.d(n,{D:()=>d});var t=i(319),a=i.n(t),l=i(46732),o={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ExpandablePostCardReaderButton_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"collection"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}},{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}},{kind:"Field",name:{kind:"Name",value:"clapCount"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ClapMutation_post"}}]}}].concat(a()(l.JP.definitions))},d={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ExpandablePostCardOverflowButton_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"creator"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"ExpandablePostCardReaderButton_post"}}]}}].concat(a()(o.definitions))}},78060:(e,n,i)=>{"use strict";i.d(n,{u:()=>de});var t=i(67294),a=i(67154),l=i.n(a),o=i(63038),d=i.n(o),r=i(59713),s=i.n(r),c=i(64718),m=i(14045),u=i(24415),k=i(75150),v=i(32947),p=i(87166),f=i(66021),S=i(31048),N=i(16880),F=i(76101),E=i(8981),C=i(48502),g=i(74302),h=i(6443),y=i(39507),b=i(18733),P=i(38352),D=i(62),w=i(75765),I=i(37774),T=i(1383),_=i(73917),x=i(93310),O=i(7955),M=i(87691),R=i(14646),B=i(92661),U=i(97217),A=i(43487),V=i(43303),L=i(68894),j=i(50458),K=i(319),q=i.n(K),z=i(36736),W=i(91727),H=i(48172),Q={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ExpandablePostCardEditorWriterButton_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"collection"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"slug"}}]}},{kind:"Field",name:{kind:"Name",value:"allowResponses"}},{kind:"Field",name:{kind:"Name",value:"clapCount"}},{kind:"Field",name:{kind:"Name",value:"visibility"}},{kind:"Field",name:{kind:"Name",value:"mediumUrl"}},{kind:"Field",name:{kind:"Name",value:"responseDistribution"}},{kind:"FragmentSpread",name:{kind:"Name",value:"useIsPinnedInContext_post"}},{kind:"FragmentSpread",name:{kind:"Name",value:"CopyFriendLinkMenuItem_post"}},{kind:"FragmentSpread",name:{kind:"Name",value:"NewsletterV3EmailToSubscribersMenuItem_post"}},{kind:"FragmentSpread",name:{kind:"Name",value:"OverflowMenuItemUndoClaps_post"}}]}}].concat(q()(z.x.definitions),q()([{kind:"FragmentDefinition",name:{kind:"Name",value:"CopyFriendLinkMenuItem_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}}]),q()(W.S.definitions),q()(H.g.definitions))},$={kind:"Document",definitions:[{kind:"OperationDefinition",operation:"query",name:{kind:"Name",value:"ExpandablePostCardEditorWriterButtonQuery"},variableDefinitions:[{kind:"VariableDefinition",variable:{kind:"Variable",name:{kind:"Name",value:"postId"}},type:{kind:"NonNullType",type:{kind:"NamedType",name:{kind:"Name",value:"ID"}}}}],selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"post"},arguments:[{kind:"Argument",name:{kind:"Name",value:"id"},value:{kind:"Variable",name:{kind:"Name",value:"postId"}}}],selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"ExpandablePostCardEditorWriterButton_post"}}]}}]}}].concat(q()(Q.definitions))};function G(e,n){var i=Object.keys(e);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(e);n&&(t=t.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),i.push.apply(i,t)}return i}function X(e){for(var n=1;n<arguments.length;n++){var i=null!=arguments[n]?arguments[n]:{};n%2?G(Object(i),!0).forEach((function(n){s()(e,n,i[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(i)):G(Object(i)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(i,n))}))}return e}var J=function(e){var n=(0,c.a)($,{variables:{postId:e.post.id}}).data;if(null==n||!n.post)return null;var i=X(X({},e),{},{post:n.post});return t.createElement(Y,i)},Y=function(e){var n=e.post,i=e.publisherContext,a=e.isEditor,o=e.isWriter,r=e.creator,s=(0,R.I)(),c=(0,b.Uo)(),K=(0,A.v9)((function(e){return e.config.authDomain})),q=n.id,z=n.collection,W=n.responseDistribution,H=n.visibility,Q=n.mediumUrl,$=n.allowResponses,G=(0,h.H)().value,X=null==G?void 0:G.id,J=null==r?void 0:r.id,Y=(0,y.T)(n).viewerEdge,Z=z||{id:"",name:""},ee=Z.id,ne=Z.name,ie=(0,L.O)(!1),te=d()(ie,3),ae=te[0],le=te[1],oe=te[2],de=(0,C.n_)(n,i),re=d()(de,2),se=re[0],ce=re[1],me=t.useState(""),ue=d()(me,2),ke=ue[0],ve=ue[1],pe=t.useCallback((function(){oe(),ce().then((function(e){var n=e.errors;n&&n.length&&n[0].message?ve(n[0].message):window.location.reload()}))}),[oe,ce,ve]),fe=(0,E.yb)(n),Se=(0,L.O)(!1),Ne=d()(Se,3),Fe=Ne[0],Ee=Ne[1],Ce=Ne[2],ge=t.useCallback((function(){fe(z).then((function(){return window.location.reload()}))}),[ee,fe]),he=(0,p.j)(q),ye=d()(he,1)[0],be=(0,L.O)(!1),Pe=d()(be,3),De=Pe[0],we=Pe[1],Ie=Pe[2],Te=(0,B.qt)("ShowHome",{}),_e=t.useCallback((function(){ye().then((function(){window.location.assign(Te)}))}),[ye,Te]),xe=W===U.Et.DISTRIBUTED,Oe=(0,L.O)(!1),Me=d()(Oe,3),Re=Me[0],Be=Me[1],Ue=Me[2],Ae={buttonStyle:"ERROR",cancelText:"Cancel"},Ve="ExpandablePostCardEditorWriterMenu",Le="Delete story".concat(xe?" and response":""),je=xe?g.Q:t.createElement(m.M,null),Ke="LOCKED"===H,qe="User"===i&&o||"Collection"===i&&a,ze=function(){xe&&(oe(),Be())};return t.createElement(t.Fragment,null,t.createElement(T.Q,l()({},Ae,{isVisible:Fe,onConfirm:ge,hide:Ce,titleText:"Remove story",confirmText:"Remove",isDestructiveAction:!0}),"Are you sure you want to remove this story from ",ne,"?"),t.createElement(T.Q,l()({},Ae,{isVisible:De,onConfirm:_e,hide:Ie,titleText:Le,confirmText:"Delete",isDestructiveAction:!0}),je),t.createElement(T.Q,{buttonStyle:"STRONG",cancelText:"Cancel",isVisible:Re,onConfirm:function(){var e=(0,j.d0)(K,q);window.location.replace(e)},hide:Ue,titleText:"Edit story and response",confirmText:"Continue",isDestructiveAction:!1},g.t),t.createElement(_.J,{ariaId:Ve,hide:oe,isVisible:ae,popoverRenderFn:function(){return t.createElement(P.mX,null,t.createElement(v.l,{type:"popover",handleClick:ze,href:(0,j.d0)(K,q)},"Edit story"),(a||o&&"User"===i)&&t.createElement(P.Sl,null,t.createElement(x.r,{onClick:pe},se?"Unpin":"Pin"," story")),t.createElement(S.w4,{post:n,onClick:oe,menuStyle:"TEXT"}),t.createElement(P.oK,null),t.createElement(P.Sl,null,t.createElement(x.r,{href:(0,j.KI)(K,q)},"Story settings")),t.createElement(P.Sl,null,t.createElement(x.r,{href:(0,j.T0)(K,q)},"Story stats")),Ke&&Q&&(null==Y?void 0:Y.shareKey)&&t.createElement(N.$,{post:n,shareKey:null==Y?void 0:Y.shareKey}),t.createElement(P.oK,null),qe?t.createElement(F.r,{hidePopover:oe,postId:n.id,allowResponses:$}):null,ee&&t.createElement(P.Sl,null,t.createElement(x.r,{onClick:Ee},"Remove story from publication")),o&&t.createElement(P.Sl,null,t.createElement("div",{className:s({color:c.baseTheme.colorTokens.foreground.error.primary.base})},t.createElement(x.r,{onClick:(0,V.B)(oe,we)},"Delete story"))),a&&!o&&t.createElement(t.Fragment,null,t.createElement(P.oK,null),t.createElement(k.T,{post:n,hidePopover:oe}),t.createElement(I.z,{targetUserId:J,postId:n.id,hidePopover:oe,viewerId:X}),t.createElement(f.q,{hidePopover:oe,creator:r}),t.createElement(D.F,{hidePopover:oe,creator:r,viewer:G}),t.createElement(w.j,{hidePopover:oe,creator:r,viewer:G})))}},t.createElement(u.c,{"aria-controls":Ve,"aria-expanded":ae?"true":"false","aria-label":"More options",onClick:le,tooltipText:"More"})),t.createElement(O.F,{isVisible:!!ke,hide:function(){return ve("")},duration:5e3},t.createElement(M.F,{scale:"M"},ke)))},Z=i(27517),ee=i(59250),ne=i(13195),ie=i(25550),te=i(83486),ae=i(51681),le=function(e){var n=e.post,i=e.viewer,a=n.creator,l=null==a?void 0:a.id,o=(0,L.O)(!1),r=d()(o,3),s=r[0],c=r[1],m=r[2],k="expandablePostCardReaderMenu",v=(0,ie.r)().viewerId,p=(0,y.T)(n).viewerEdge,S=(0,ee.jM)(),N=S.mutedAuthorIds,F=S.setMutedAuthorIds,E=S.mutedPubIds,C=S.setMutedPubIds,g=S.isMutingFromHomeFeed,h=t.useCallback((function(e){F([].concat(q()(N),[e]))}),[N]),b=t.useCallback((function(e){C([].concat(q()(E),[e]))}),[E]),T=(0,Z.I0)(),O=t.useCallback((function(e){return T((0,te.at)(e))}),[T]),M=(0,A.b$)((function(e){return e.multiVote.clapsPerPost})),R=(0,ae.l)(M,n,p),B=R.clapCount,U=R.viewerClapCount,V=(0,ne.CP)();if(!l)return null;var j=v&&B&&U&&U>0;return t.createElement(_.J,{ariaId:k,hide:m,isVisible:s,popoverRenderFn:function(){return t.createElement(P.mX,null,!!j&&t.createElement(P.Sl,null,t.createElement(x.r,{onClick:function(){return V(n,(null==i?void 0:i.id)||"",-U,p),O({postId:n.id,clapCount:B-U,viewerClapCount:0,viewerHasClappedSinceFetch:!0}),void m()}},"Undo applause for this post")),t.createElement(I.z,{targetUserId:l,postId:n.id,hidePopover:m,viewerId:v}),t.createElement(f.q,{hidePopover:m,creator:a,setMutedAuthorId:h,setMutedPubId:b,isMutingFromHomeFeed:g}),t.createElement(D.F,{hidePopover:m,creator:a,viewer:i}),t.createElement(w.j,{hidePopover:m,creator:a,viewer:i}))}},t.createElement(u.c,{"aria-controls":k,"aria-expanded":s?"true":"false","aria-label":"More options",onClick:c,tooltipText:"More"}))},oe=i(67701),de=function(e){var n=e.post,i=e.publisherContext,a=(0,h.H)().value,l=(0,oe.gY)(n.collection).viewerEdge,o=!(null==l||!l.isEditor),d=n.creator,r=(null==a?void 0:a.id)===(null==d?void 0:d.id);return a?o||r?t.createElement(J,{post:n,isEditor:o,isWriter:r,publisherContext:i,creator:d}):t.createElement(le,{post:n,viewer:a}):null}},48342:(e,n,i)=>{"use strict";i.d(n,{K:()=>d});var t=i(67294),a=i(14646),l=i(21372),o=function(e){return{color:e.baseColor.text.lighter}},d=function(e){var n=e.readingTime,i=e.isLighterText,d=void 0!==i&&i,r=(0,a.I)();if(!n)return null;var s="".concat((0,l.Vd)(n)," min read");return t.createElement("span",{className:d?r(o):void 0},s)}},85256:(e,n,i)=>{"use strict";i.d(n,{z:()=>t});var t=function(e){switch(e){case"PUBLIC":return 0;case"UNLISTED":return 1;case"LOCKED":return 2;default:return}}},89748:(e,n,i)=>{"use strict";i.d(n,{yu:()=>m,br:()=>u,We:()=>k,Gk:()=>v});var t=i(319),a=i.n(t),l=i(62549),o=i(82864),d=i(17828),r=i(18821),s=i(68216),c=i(54341),m={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"CardByline_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"DraftStatus_post"}},{kind:"FragmentSpread",name:{kind:"Name",value:"Star_post"}},{kind:"FragmentSpread",name:{kind:"Name",value:"shouldShowPublishedInStatus_post"}}]}}].concat(a()(l.t.definitions),a()(o.W.definitions),a()(d.w.definitions))},u={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"CardByline_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"username"}},{kind:"Field",name:{kind:"Name",value:"mediumMemberAt"}},{kind:"Field",name:{kind:"Name",value:"socialStats"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"followerCount"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"useIsVerifiedBookAuthor_user"}},{kind:"FragmentSpread",name:{kind:"Name",value:"userUrl_user"}},{kind:"FragmentSpread",name:{kind:"Name",value:"UserMentionTooltip_user"}}]}}].concat(a()(r.H.definitions),a()(s.$m.definitions),a()(c.O.definitions))},k={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"CardByline_collection"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Collection"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"FragmentSpread",name:{kind:"Name",value:"collectionUrl_collection"}}]}}].concat(a()(s.nf.definitions))},v={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"CardByline_publisher"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Publisher"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"InlineFragment",typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"CardByline_user"}}]}},{kind:"InlineFragment",typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Collection"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"CardByline_collection"}}]}}]}}].concat(a()(u.definitions),a()(k.definitions))}},68717:(e,n,i)=>{"use strict";i.d(n,{Q:()=>w,u:()=>I});var t=i(67294),a=i(35989),l=i(68427),o=i(84739),d=i(65968),r=i(64238),s=i(21309),c=i(60765),m=i(63459),u=i(17311),k=i(34796),v=i(35473),p=i(28695),f=i(77355),S=i(26244),N=i(21755),F=i(87691),E=i(18155),C=i(14646),g=i(17583),h=i(58992);function y(e,n){return n&&(0,E.nE)(e)?e[n]:e}var b=function(e){var n=e.author,i=e.forceSize,a=e.scale,l=void 0===a?"M":a,s=(0,g.s)(),m=(0,o.B)(n),u=(0,r.o)(n),k=s===N.j.xs;if(!n||!n.name)return null;var v=t.createElement(c.g,{href:m},t.createElement(f.x,{display:"flex",flexWrap:"nowrap",alignItems:"center"},t.createElement(F.F,{color:"ACCENT",scale:y(l,i)},n.name),u&&t.createElement(f.x,{marginLeft:"2px",marginTop:"1px"},t.createElement(d._,{size:"S"}))));return t.createElement(f.x,{display:"flex",alignItems:"center"},k?v:t.createElement(S.$,{placement:"right",targetDistance:15,mouseLeaveDelay:200,popoverRenderFn:function(){return t.createElement(p.K,{user:n})}},v))},P=function(e){var n=e.collection,i=e.forceSize,a=e.scale,o=void 0===a?"M":a,d=e.post,r=(0,l.R)(n);return(0,h.l)(d)?t.createElement(c.g,{href:r},t.createElement(F.F,{scale:y(o,i),color:"DARKER"},"Published in ",t.createElement(s.t,{collection:n}))):null},D=function(e){var n=e.small,i=void 0!==n&&n,a=e.hideDot,l=void 0!==a&&a,o=(0,C.I)();return t.createElement("span",{className:o({margin:"0 ".concat(i?4:7,"px")})},l?null:"·")},w=function(e){var n=e.datePrefix,i=void 0===n?"":n,l=e.forceSize,o=e.isOneLine,d=e.withMidDot,r=void 0===d||d,s=e.href,v=e.onClick,p=e.publishedAt,S=e.scale,N=void 0===S?"M":S,E=e.showStar,C=void 0!==E&&E,g=e.showPinned,h=void 0!==g&&g,b=e.timeColor,P=void 0===b?"LIGHTER":b,w=e.timeToRead,I=e.post;if(!p&&!w)return null;var T=o?u.h:m.E;return t.createElement(f.x,{display:"flex",alignItems:"center"},t.createElement(c.g,{href:s,onClick:v},t.createElement(F.F,{color:P,scale:y(N,l)},o&&r&&t.createElement(D,{small:!0,hideDot:!!w&&!!p}),p&&!h?t.createElement(t.Fragment,null,i,t.createElement(T,{hasPrefix:!(!o||!i)||void 0,timestamp:p})):null,h?t.createElement("span",null,"Pinned"):null,p&&w?t.createElement(D,null):null,w||null,!p&&t.createElement(t.Fragment,null,t.createElement(D,{small:o}),t.createElement(F.F,{color:"DARKER",scale:y(N,l),tag:"span"},t.createElement(k.FV,{post:I}))))),C&&t.createElement(a.U,{padding:"0 0 0 4px",post:I}))},I=function(e){var n=e.avatar,i=void 0===n?null:n,a=e.datePrefix,l=e.forceSize,o=e.hideAuthor,d=void 0!==o&&o,r=e.href,s=e.onClick,c=e.isOneLine,m=void 0!==c&&c,u=e.publisher,k=e.publishedAt,p=e.scale,f=e.showStar,S=void 0!==f&&f,N=e.showPinned,F=void 0!==N&&N,E=e.timeColor,C=e.timeToRead,g=e.post,h=null;"Collection"===u.__typename?h=t.createElement(P,{collection:u,forceSize:l,scale:p,post:g}):d||(h=t.createElement(b,{author:u,forceSize:l,scale:p}));var y="Collection"===u.__typename||!d;return t.createElement(v.Y,{avatar:d?null:i,isOneLine:m,title:h,description:t.createElement(w,{datePrefix:a,publishedAt:k,timeToRead:C,withMidDot:y,href:r,onClick:s,showStar:S,showPinned:F,forceSize:l,scale:p,timeColor:E,isOneLine:m,post:g})})}},18305:(e,n,i)=>{"use strict";i.d(n,{o:()=>v,h:()=>p});var t=i(28655),a=i.n(t),l=i(92471),o=i(67294),d=i(85256),r=i(18627),s=i(66411),c=i(14646),m=i(18122);function u(){var e=a()(["\n  fragment PostPresentationTracker_post on Post {\n    id\n    visibility\n    previewContent {\n      isFullContent\n    }\n    collection {\n      id\n      slug\n    }\n  }\n"]);return u=function(){return e},e}var k={width:"100%",height:"100%"};function v(e){var n=e.post,i=e.presentationContext,t=e.suppressedEvents,a=e.children,l=e.isDisplayingFullPost,u=e.reportClientViewedOnFullPost,v=e.postClientViewedContext,p=e.pinned,f=e.shouldReportClientViewed,S=void 0===f||f,N=e.referrerSource,F=(0,c.I)(),E=(0,r.Av)(),C=(0,s.pK)(),g=o.useCallback((function(){if(n&&"ALL"!==t){var e=n.visibility,a=n.previewContent,o=n.collection,r=null!==l?l:a&&a.isFullContent,s=N?{referrerSource:N}:void 0;"PRESENTED"!==t&&E.event("post.clientPresented",{postId:n.id,source:C,collectionId:o?o.id:null,isFullPost:r,pinned:p,postVisibility:(0,d.z)(e),context:"POST_PREVIEW"!==i?i.toLowerCase():null},s),u&&r&&"VIEWED"!==t&&S&&E.event("post.clientViewed",{postId:n.id,source:C,collectionId:o?o.id:null,collectionSlug:o?o.slug:null,context:v,isFriendLink:!1,pinned:p})}}),[n,t,i,p,N,C]),h=(0,m.g)({onPresentedFn:g});return o.createElement("div",{className:F(k),ref:h},a)}var p=(0,l.Ps)(u())},69724:(e,n,i)=>{"use strict";i.d(n,{k:()=>t});var t={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostScrollTracker_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"collection"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}},{kind:"Field",name:{kind:"Name",value:"sequence"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"sequenceId"}}]}}]}}]}},68821:(e,n,i)=>{"use strict";i.d(n,{V:()=>c});var t=i(23493),a=i.n(t),l=i(67294),o=i(18627),d=i(66411),r=i(34135),s=i(84509);function c(e,n,i){var t=(0,o.Av)(),c=(0,d.Qi)(),m=Date.now(),u=null,k=l.useCallback(a()((function(){if(e.current){var i=(0,s.L6)(e.current);if((0,s.pn)(i)){var a=Date.now(),l=(0,s.tM)(i),o=(0,s.UO)(),d=(0,s.t_)(),r=Math.round(l.top),k=Math.round(l.top+l.height),v=o.top,p=o.top+d.height,f=o.height,S={postIds:[n.id],collectionIds:[n.collection?n.collection.id:""],sequenceIds:[n.sequence?n.sequence.sequenceId:""],sources:[c],tops:[r],bottoms:[k],areFullPosts:[!0],loggedAt:a,timeDiff:null!==u?Math.round(a-u):0,scrollTop:v,scrollBottom:p,scrollableHeight:f,viewStartedAt:m};t.event("post.streamScrolled",S),u=a}}}),1e3),[n]);l.useEffect((function(){k();var e=null!=i&&i.current?(0,r.jC)(null==i?void 0:i.current):r.V6;return e.on("scroll_end",k),function(){e.off("scroll_end",k)}}),[k])}},81494:(e,n,i)=>{"use strict";i.d(n,{O1:()=>l}),i(59713);var t=i(67294),a=t.createContext(null),l=function(e){var n=e.event,i=e.children;return t.createElement(a.Provider,{value:{event:n}},i)}},17828:(e,n,i)=>{"use strict";i.d(n,{w:()=>t});var t={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"shouldShowPublishedInStatus_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"statusForCollection"}},{kind:"Field",name:{kind:"Name",value:"isPublished"}}]}}]}}}]);
//# sourceMappingURL=https://stats.medium.build/lite/sourcemaps/5510.e4d9498b.chunk.js.map

}
/*
     FILE ARCHIVED ON 10:34:19 May 19, 2023 AND RETRIEVED FROM THE
     INTERNET ARCHIVE ON 10:16:30 May 16, 2024.
     JAVASCRIPT APPENDED BY WAYBACK MACHINE, COPYRIGHT INTERNET ARCHIVE.

     ALL OTHER CONTENT MAY ALSO BE PROTECTED BY COPYRIGHT (17 U.S.C.
     SECTION 108(a)(3)).
*/
/*
playback timings (ms):
  captures_list: 1.331
  exclusion.robots: 0.177
  exclusion.robots.policy: 0.157
  esindex: 0.017
  cdx.remote: 7.746
  LoadShardBlock: 105.664 (3)
  PetaboxLoader3.datanode: 47.239 (5)
  PetaboxLoader3.resolve: 132.945 (4)
  load_resource: 79.424 (2)
*/