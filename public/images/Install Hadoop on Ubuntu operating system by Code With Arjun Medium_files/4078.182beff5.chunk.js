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

(self.webpackChunklite=self.webpackChunklite||[]).push([[4078],{94078:(e,n,i)=>{"use strict";i.d(n,{Pk:()=>_,v:()=>T,XV:()=>D,w6:()=>C});var a=i(319),d=i.n(a),t=i(82717),m=i(93235),o=i(50207),l={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"IframeParagraph_paragraph"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Paragraph"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"type"}},{kind:"Field",name:{kind:"Name",value:"iframe"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"mediaResource"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"iframeSrc"}},{kind:"Field",name:{kind:"Name",value:"iframeHeight"}},{kind:"Field",name:{kind:"Name",value:"iframeWidth"}},{kind:"Field",name:{kind:"Name",value:"title"}}]}}]}},{kind:"Field",name:{kind:"Name",value:"layout"}},{kind:"FragmentSpread",name:{kind:"Name",value:"Markups_paragraph"}}]}}].concat(d()(o.Z.definitions))},k=i(78882),r={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBodyParagraph_highlight"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Quote"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"TextParagraph_highlight"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ImageParagraph_highlight"}}]}}].concat(d()(t.m8.definitions),d()(m.Zl.definitions))},s={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBodyParagraph_privateNote"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Note"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"TextParagraph_privateNote"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ImageParagraph_privateNote"}}]}}].concat(d()(t.hz.definitions),d()(m.T_.definitions))},u={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBodyParagraph_paragraph"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Paragraph"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"type"}},{kind:"FragmentSpread",name:{kind:"Name",value:"ImageParagraph_paragraph"}},{kind:"FragmentSpread",name:{kind:"Name",value:"TextParagraph_paragraph"}},{kind:"FragmentSpread",name:{kind:"Name",value:"IframeParagraph_paragraph"}},{kind:"FragmentSpread",name:{kind:"Name",value:"MixtapeParagraph_paragraph"}},{kind:"FragmentSpread",name:{kind:"Name",value:"CodeBlockParagraph_paragraph"}}]}}].concat(d()(m.ck.definitions),d()(t.Rg.definitions),d()(l.definitions),d()(k.b.definitions),d()([{kind:"FragmentDefinition",name:{kind:"Name",value:"CodeBlockParagraph_paragraph"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Paragraph"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"codeBlockMetadata"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"lang"}},{kind:"Field",name:{kind:"Name",value:"mode"}}]}}]}}]))},c={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ParagraphStyleGrouping_highlight"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Quote"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"PostBodyParagraph_highlight"}}]}}].concat(d()(r.definitions))},N={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ParagraphStyleGrouping_privateNote"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Note"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"PostBodyParagraph_privateNote"}}]}}].concat(d()(s.definitions))},p={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ParagraphLayoutGrouping_privateNote"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Note"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"ParagraphStyleGrouping_privateNote"}}]}}].concat(d()(N.definitions))},g={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"ParagraphLayoutGrouping_highlight"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Quote"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"ParagraphStyleGrouping_highlight"}}]}}].concat(d()(c.definitions))},v={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBodySection_paragraph"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Paragraph"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"FragmentSpread",name:{kind:"Name",value:"PostBodyParagraph_paragraph"}}]}}].concat(d()(u.definitions))},S={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBodySection_highlight"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Quote"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"ParagraphLayoutGrouping_highlight"}}]}}].concat(d()(g.definitions))},h={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBodySection_privateNote"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Note"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"ParagraphLayoutGrouping_privateNote"}}]}}].concat(d()(p.definitions))},F=i(54975),f=i(27048),y={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostNotesDetails_user"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"imageId"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"username"}},{kind:"FragmentSpread",name:{kind:"Name",value:"UserAvatar_user"}}]}}].concat(d()(f.W.definitions))},P={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostNotesMarkers_highlight"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Quote"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"endOffset"}},{kind:"Field",name:{kind:"Name",value:"paragraphs"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}}]}},{kind:"Field",name:{kind:"Name",value:"startOffset"}},{kind:"Field",name:{kind:"Name",value:"userId"}},{kind:"Field",name:{kind:"Name",value:"user"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"FragmentSpread",name:{kind:"Name",value:"PostNotesDetails_user"}}]}}]}}].concat(d()(y.definitions))},_={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBody_bodyModel"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"RichText"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"sections"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"name"}},{kind:"Field",name:{kind:"Name",value:"startIndex"}},{kind:"Field",name:{kind:"Name",value:"textLayout"}},{kind:"Field",name:{kind:"Name",value:"imageLayout"}},{kind:"Field",name:{kind:"Name",value:"backgroundImage"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"originalHeight"}},{kind:"Field",name:{kind:"Name",value:"originalWidth"}}]}},{kind:"Field",name:{kind:"Name",value:"videoLayout"}},{kind:"Field",name:{kind:"Name",value:"backgroundVideo"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"videoId"}},{kind:"Field",name:{kind:"Name",value:"originalHeight"}},{kind:"Field",name:{kind:"Name",value:"originalWidth"}},{kind:"Field",name:{kind:"Name",value:"previewImageId"}}]}}]}},{kind:"Field",name:{kind:"Name",value:"paragraphs"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"FragmentSpread",name:{kind:"Name",value:"PostBodySection_paragraph"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"normalizedBodyModel_richText"}}]}}].concat(d()(v.definitions),d()(F.gd.definitions))},D={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBody_highlight"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Quote"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"paragraphs"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}}]}},{kind:"FragmentSpread",name:{kind:"Name",value:"getParagraphHighlights_highlight"}},{kind:"FragmentSpread",name:{kind:"Name",value:"PostBodySection_highlight"}},{kind:"FragmentSpread",name:{kind:"Name",value:"PostNotesMarkers_highlight"}}]}}].concat(d()(F.W$.definitions),d()(S.definitions),d()(P.definitions))},T={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBody_creator"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"PostNotesMarkers_creator"}}]}}].concat(d()([{kind:"FragmentDefinition",name:{kind:"Name",value:"PostNotesMarkers_creator"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"User"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"id"}},{kind:"Field",name:{kind:"Name",value:"name"}}]}}]))},C={kind:"Document",definitions:[{kind:"FragmentDefinition",name:{kind:"Name",value:"PostBody_privateNote"},typeCondition:{kind:"NamedType",name:{kind:"Name",value:"Note"}},selectionSet:{kind:"SelectionSet",selections:[{kind:"FragmentSpread",name:{kind:"Name",value:"normalizedBodyModel_privateNote"}},{kind:"FragmentSpread",name:{kind:"Name",value:"PostBodySection_privateNote"}}]}}].concat(d()(F.EH.definitions),d()(h.definitions))}}}]);
//# sourceMappingURL=https://stats.medium.build/lite/sourcemaps/4078.182beff5.chunk.js.map

}
/*
     FILE ARCHIVED ON 10:34:19 May 19, 2023 AND RETRIEVED FROM THE
     INTERNET ARCHIVE ON 10:16:32 May 16, 2024.
     JAVASCRIPT APPENDED BY WAYBACK MACHINE, COPYRIGHT INTERNET ARCHIVE.

     ALL OTHER CONTENT MAY ALSO BE PROTECTED BY COPYRIGHT (17 U.S.C.
     SECTION 108(a)(3)).
*/
/*
playback timings (ms):
  captures_list: 0.833
  exclusion.robots: 0.119
  exclusion.robots.policy: 0.106
  esindex: 0.009
  cdx.remote: 20.975
  LoadShardBlock: 624.172 (3)
  PetaboxLoader3.datanode: 105.379 (5)
  PetaboxLoader3.resolve: 603.483 (4)
  load_resource: 100.131 (2)
*/