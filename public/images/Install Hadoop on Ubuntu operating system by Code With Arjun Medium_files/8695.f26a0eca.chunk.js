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

(self.webpackChunklite=self.webpackChunklite||[]).push([[8695],{17311:(e,n,i)=>{"use strict";i.d(n,{h:()=>d});var t=i(76972),a=i(94673),l=i(63459);function d(e){var n=e.hasPrefix,i=void 0!==n&&n,d=e.timestamp,o=Date.now(),r=(0,t.Z)(o,d);if(0===r)return i?"just now":"Just now";if(r>=1&&r<24)return"".concat(r," hour").concat(r>1?"s":""," ago");var m=(0,a.Z)(o,d);return m>=1&&m<7?"".concat(m," day").concat(m>1?"s":""," ago"):(0,l.E)({timestamp:d})}},14294:(e,n,i)=>{"use strict";i.d(n,{P:()=>s});var t=i(68337),a=i.n(t),l=i(67294),d=i(76134),o=i.n(d),r=i(93310),m=i(14646),s=function(e){var n=e.children,i=e.linkifyTwitterHandles,t=void 0!==i&&i,d=e.wrapLinks,s=void 0!==d&&d,u=e.target,c=(0,m.I)();if(!n)return null;var k=a()().tlds(o());t&&k.add("@",{validate:function(e,n,i){var t=e.slice(n);return i.re.twitter||(i.re.twitter=new RegExp("^([a-zA-Z0-9_]){1,15}(?!_)(?=$|"+i.re.src_ZPCc+")")),i.re.twitter.test(t)?!(n>=2&&"@"===t[n-2])&&t.match(i.re.twitter)[0].length:0},normalize:function(e){e.url="https://web.archive.org/web/20230519103419/https://twitter.com/"+e.url.replace(/^@/,"")}});var p=k.match(n);if(!p)return l.createElement("span",{className:c({wordBreak:"break-word"})},n);var v=0;return p.reduce((function(e,i,t){return n?(i.index>v&&e.push(n.substring(v,i.index)),e.push(l.createElement(r.r,{wrapLinks:s,disableSourceParam:!0,key:t,inline:!0,linkStyle:"OBVIOUS",href:i.url,target:u},i.text)),t===p.length-1&&i.lastIndex<n.length&&e.push(n.substring(i.lastIndex,n.length)),v=i.lastIndex,e):[]}),[])}},78693:(e,n,i)=>{"use strict";i.d(n,{S:()=>m,s:()=>r});var t=i(319),a=i.n(t),l=i(66081),d={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"UserFollowButtonSignedOut_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"SusiClickable_user"}}]}}].concat(a()(l.Vm.definitions))},o={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"UserFollowButtonSignedOut_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"SusiClickable_post"}}]}}].concat(a()(l.qU.definitions))},r={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"UserFollowButton_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"UserFollowButtonSignedIn_user"}},{kind:"FragmentSpread",name:{kind:"Name",value:"UserFollowButtonSignedOut_user"}}]}}].concat(a()([{kind:"FragmentDefinition",name:{kind:"Name",value:"UserFollowButtonSignedIn_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}}]}}]),a()(d.definitions))},m={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"UserFollowButton_post"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Post"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"collection"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"UserFollowButtonSignedOut_post"}}]}}].concat(a()(o.definitions))}},54341:(e,n,i)=>{"use strict";i.d(n,{O:()=>r,r:()=>m});var t=i(319),a=i.n(t),l=i(27048),d=i(78693),o=i(18821),r={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"UserMentionTooltip_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"username"}},{kind:"Field",name:{kind:"Name",value:"bio"}},{kind:"Field",name:{kind:"Name",value:"imageId"}},{kind:"Field",name:{kind:"Name",value:"mediumMemberAt"}},{kind:"FragmentSpread",name:{kind:"Name",value:"UserAvatar_user"}},{kind:"FragmentSpread",name:{kind:"Name",value:"UserFollowButton_user"}},{kind:"FragmentSpread",name:{kind:"Name",value:"useIsVerifiedBookAuthor_user"}}]}}].concat(a()(l.W.definitions),a()(d.s.definitions),a()(o.H.definitions))},m={kind:"Document",definitions:[{kind:"OperationDefinition",operation:"query",name:{kind:"Name",value:"UserMentionTooltipStatsQuery"},variableDefinitions:[{kind:"VariableDefinition",variable:{kind:"Variable",name:{kind:"Name",value:"id"}},type:{kind:"NonNullType",type:{kind:"NamedType",name:{kind:"Name",value:"ID"}}}}],selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"userResult"},arguments:[{kind:"Argument",name:{kind:"Name",value:"id"},value:{kind:"Variable",name:{kind:"Name",value:"id"}}}],selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"__typename"}},{kind:"InlineFragment",typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"socialStats"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"followerCount"}}]}},{kind:"Field",name:{kind:"Name",value:"viewerEdge"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"createdAt"}},{kind:"Field",name:{kind:"Name",value:"lastPostCreatedAt"}}]}}]}}]}}]}}]}},28695:(e,n,i)=>{"use strict";i.d(n,{u:()=>E,K:()=>y});var t=i(64718),a=i(93022),l=i(23450),d=i.n(l),o=i(67294),r=i(84739),m=i(65968),s=i(64238),u=i(17311),c=i(14294),k=i(17193),p=i(32317),v=i(54341),S=i(77355),g=i(27323),f=i(20113),N=i(87691),x=i(14646),w=i(43487),h=i(45932),F=i(21372),E=function(){var e=(0,x.I)(),n=(0,h.P)();return o.createElement("div",{className:e((function(){return n}))},o.createElement(S.x,{display:"flex",flexDirection:"row",alignItems:"flex-start",justifyContent:"space-between",padding:"12px",width:"280px",backgroundColor:"BACKGROUND"},o.createElement(S.x,{width:"100%"},o.createElement(S.x,{display:"flex",flexDirection:"row",alignItems:"center",marginBottom:"20px"},o.createElement(S.x,{height:"20px",width:"20px",backgroundColor:"BASE_NORMAL",borderRadius:"50%",marginRight:"8px"}),o.createElement(S.x,{height:"8px",width:"82px",backgroundColor:"BASE_NORMAL"})),o.createElement(S.x,{width:"80%",height:"8px",marginBottom:"12px",backgroundColor:"BASE_NORMAL"}),o.createElement(S.x,{width:"65%",height:"8px",marginBottom:"12px",backgroundColor:"BASE_NORMAL"}),o.createElement(S.x,{width:"85%",height:"8px",marginBottom:"12px",backgroundColor:"BASE_NORMAL"}),o.createElement(S.x,{width:"70%",height:"8px",marginBottom:"12px",backgroundColor:"BASE_NORMAL"}))))},y=function(e){var n,i,l=e.user,x=(0,w.v9)((function(e){return e.config.productName})),h=l.id,E=l.name,y=l.username,b=l.bio,C=l.imageId,_=l.mediumMemberAt,A=l.hasSubdomain,B=l.customDomainState,D=(0,t.a)(v.r,{variables:{id:h}}).data,U=(0,r.B)(l),T=(0,s.o)(l);if("User"===(null==D||null===(n=D.userResult)||void 0===n?void 0:n.__typename)){var I=D.userResult,O=I.socialStats,R=I.viewerEdge,L=R.createdAt,M=R.lastPostCreatedAt,P=(0,F.pY)((null==O?void 0:O.followerCount)||0);if(null!=O&&O.followerCount&&(null==O?void 0:O.followerCount)>=100&&(i="".concat(P," Followers")),M)i=o.createElement(o.Fragment,null,"Last published ",o.createElement(u.h,{timestamp:M,hasPrefix:!0}));else if(!M&&null!=O&&O.followerCount&&(null==O?void 0:O.followerCount)>0)i="".concat(P," ").concat(d()("Follower",null==O?void 0:O.followerCount));else if(L){var V=(0,a.Z)(L,"LLL yyyy");i="Joined ".concat(x," ").concat(V)}else i=""}return o.createElement(S.x,{padding:"16px",display:"flex",flexDirection:"column",width:"300px",playwrightClassName:"pw-user-tooltip"},o.createElement(S.x,{display:"flex",flexDirection:"row",alignItems:"center",whiteSpace:"normal"},o.createElement(k.Yt,{scale:"XS",user:{__typename:"User",mediumMemberAt:_,username:y,name:E,imageId:C,id:h,hasSubdomain:A,customDomainState:B},link:!0}),o.createElement(g.P,{href:U},o.createElement(S.x,{display:"flex",flexDirection:"column",paddingLeft:"12px"},o.createElement(f.X6,{scale:"S",clamp:2},E)))),T&&o.createElement(S.x,{paddingTop:"12px"},o.createElement(m._,{size:"M",withText:!0})),b&&o.createElement(S.x,{paddingTop:"8px"},o.createElement(N.F,{scale:"S",color:"DARKER"},o.createElement(c.P,{wrapLinks:!0},b))),o.createElement(S.x,{display:"flex",flexDirection:"row",alignItems:"center",justifyContent:"space-between",borderTop:"BASE_LIGHTER",marginTop:"16px",paddingTop:"10px"},o.createElement(N.F,{scale:"S"},i),o.createElement(p.B,{user:l,buttonSize:"COMPACT",susiEntry:"follow_card"})))}}}]);
//# sourceMappingURL=https://stats.medium.build/lite/sourcemaps/8695.f26a0eca.chunk.js.map

}
/*
     FILE ARCHIVED ON 10:34:19 May 19, 2023 AND RETRIEVED FROM THE
     INTERNET ARCHIVE ON 10:16:14 May 16, 2024.
     JAVASCRIPT APPENDED BY WAYBACK MACHINE, COPYRIGHT INTERNET ARCHIVE.

     ALL OTHER CONTENT MAY ALSO BE PROTECTED BY COPYRIGHT (17 U.S.C.
     SECTION 108(a)(3)).
*/
/*
playback timings (ms):
  captures_list: 2.311
  exclusion.robots: 0.163
  exclusion.robots.policy: 0.14
  esindex: 0.016
  cdx.remote: 16.039
  LoadShardBlock: 686.772 (3)
  PetaboxLoader3.datanode: 623.976 (5)
  PetaboxLoader3.resolve: 156.542 (4)
  load_resource: 111.937 (2)
*/