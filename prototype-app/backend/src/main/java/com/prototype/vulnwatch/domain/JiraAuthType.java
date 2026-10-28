package com.prototype.vulnwatch.domain;

/**
 * How Scout authenticates to Jira.
 *
 * <p>{@code BASIC} is Jira Cloud's scheme — an Atlassian account email plus an API token.
 * {@code BEARER} covers Jira Data Center personal access tokens.
 */
public enum JiraAuthType {
    BASIC,
    BEARER
}
