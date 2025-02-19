import type { Action } from "entities/Action";
import type { JSAction, JSCollection } from "entities/JSCollection";
import type { ApplicationPayload } from "@appsmith/constants/ReduxActionConstants";
import store from "store";
import { getAppMode } from "@appsmith/selectors/applicationSelectors";
import { getDatasource } from "@appsmith/selectors/entitiesSelector";
import { getCurrentEnvironmentDetails } from "@appsmith/selectors/environmentSelectors";
import type { Plugin } from "api/PluginApi";
import { get, isNil } from "lodash";

export function getPluginActionNameToDisplay(action: Action) {
  return action.name;
}

export const getActionProperties = (
  action: Action,
  keyConfig: Record<string, string>,
) => {
  const actionProperties: Record<string, unknown> = {};
  Object.keys(keyConfig).forEach((key) => {
    const value = get(action, key);
    if (!isNil(value)) {
      actionProperties[keyConfig[key]] = get(action, key);
    }
  });
  return actionProperties;
};

export function getJSActionPathNameToDisplay(
  action: JSAction,
  collection: JSCollection,
) {
  return collection.name + "." + action.name;
}

export function getJSActionNameToDisplay(action: JSAction) {
  return action.name;
}

export function getCollectionNameToDisplay(
  _: JSAction,
  collectionName: string,
) {
  return collectionName;
}

export function getActionExecutionAnalytics(
  action: Action,
  plugin: Plugin,
  params: Record<string, unknown>,
  currentApp: ApplicationPayload,
  datasourceId: string,
) {
  let appMode;
  const state = store.getState();
  const datasource = getDatasource(state, datasourceId);
  const currentEnvDetails = getCurrentEnvironmentDetails(state);
  const resultObj = {
    type: action?.pluginType,
    name: action?.name,
    environmentId: currentEnvDetails.id,
    environmentName: currentEnvDetails.name,
    pluginName: plugin?.name,
    datasourceId: datasourceId,
    isMock: !!datasource?.isMock,
    actionId: action?.id,
    inputParams: Object.keys(params).length,
  };

  if (!!currentApp) {
    appMode = getAppMode(state);
    return {
      ...resultObj,
      isExampleApp: currentApp.appIsExample,
      pageId: action?.pageId,
      appId: currentApp.id,
      appMode: appMode,
      appName: currentApp.name,
    };
  }

  return resultObj;
}
