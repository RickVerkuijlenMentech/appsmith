import React, { useCallback } from "react";
import { Button } from "design-system";

import FileTabs from "./FileTabs";
import { useSelector } from "react-redux";
import { getIDEViewMode, getIsSideBySideEnabled } from "selectors/ideSelectors";
import Container from "./Container";
import { useCurrentEditorState } from "../hooks";
import type { EntityItem } from "@appsmith/entities/IDE/constants";
import {
  EditorEntityTab,
  EditorEntityTabState,
  EditorViewMode,
} from "@appsmith/entities/IDE/constants";
import { useJSAdd } from "@appsmith/pages/Editor/IDE/EditorPane/JS/hooks";
import { useQueryAdd } from "@appsmith/pages/Editor/IDE/EditorPane/Query/hooks";
import { TabSelectors } from "./constants";
import { getCurrentPageId } from "@appsmith/selectors/entitiesSelector";
import history, { NavigationMethod } from "utils/history";
import { includes } from "lodash";
import ListButton from "./ListButton";

const SplitScreenTabs = () => {
  const isSideBySideEnabled = useSelector(getIsSideBySideEnabled);
  const ideViewMode = useSelector(getIDEViewMode);
  const { segment, segmentMode } = useCurrentEditorState();

  const onJSAddClick = useJSAdd();
  const onQueryAddClick = useQueryAdd();
  const onAddClick = useCallback(() => {
    if (segmentMode === EditorEntityTabState.Add) return;
    if (segment === EditorEntityTab.JS) onJSAddClick();
    if (segment === EditorEntityTab.QUERIES) onQueryAddClick();
  }, [segment, segmentMode, onQueryAddClick, onJSAddClick]);

  const tabsConfig = TabSelectors[segment];
  const pageId = useSelector(getCurrentPageId);

  const files = useSelector(tabsConfig.tabsSelector);
  const allFilesList = useSelector(tabsConfig.listSelector);

  const onClick = useCallback(
    (item: EntityItem) => {
      const navigateToUrl = tabsConfig.itemUrlSelector(item, pageId);
      history.push(navigateToUrl, {
        invokedBy: NavigationMethod.EditorTabs,
      });
    },
    [segment],
  );

  const overflowList = allFilesList.filter((item) => !includes(files, item));

  if (!isSideBySideEnabled) return null;
  if (ideViewMode === EditorViewMode.FullScreen) return null;
  if (segment === EditorEntityTab.UI) return null;
  return (
    <Container>
      <Button
        isIconButton
        kind={"secondary"}
        onClick={onAddClick}
        startIcon={"add-line"}
      />
      <FileTabs navigateToTab={onClick} tabs={files} />
      <ListButton items={overflowList} navigateToTab={onClick} />
    </Container>
  );
};

export default SplitScreenTabs;
