import { describe, expect, it } from 'vitest';
import { RepositoryModel } from '../repository.model.js';
import { indexNamed, invalidPaths, oid } from './helpers.js';

const minimalRepository = () => ({
  providerRepoId: '1296269',
  fullName: 'acme/api',
  name: 'api',
  ownerLogin: 'acme',
  owner: oid(),
});

describe('Repository model', () => {
  it('accepts a minimal repository and applies defaults', () => {
    const repository = new RepositoryModel(minimalRepository());

    expect(invalidPaths(repository)).toEqual([]);
    expect(repository.provider).toBe('github');
    expect(repository.defaultBranch).toBe('main');
    expect(repository.scanEnabled).toBe(true);
    expect(repository.autoScanOnPush).toBe(true);
    expect(repository.isPrivate).toBe(false);
    expect(repository.isArchived).toBe(false);
    expect(repository.visibility).toBe('private');
  });

  it('requires the owner, provider id and canonical name', () => {
    expect(invalidPaths(new RepositoryModel({}))).toEqual([
      'fullName',
      'name',
      'owner',
      'ownerLogin',
      'providerRepoId',
    ]);
  });

  it('requires fullName to be "owner/name"', () => {
    expect(
      invalidPaths(new RepositoryModel({ ...minimalRepository(), fullName: 'just-a-name' })),
    ).toContain('fullName');
    expect(
      invalidPaths(new RepositoryModel({ ...minimalRepository(), fullName: 'a/b/c' })),
    ).toContain('fullName');
    expect(
      invalidPaths(new RepositoryModel({ ...minimalRepository(), fullName: 'acme/api.v2' })),
    ).toEqual([]);
  });

  it('validates clone URLs as http(s) and sshUrl as a git remote', () => {
    const repository = new RepositoryModel({
      ...minimalRepository(),
      cloneUrl: 'https://github.com/acme/api.git',
      sshUrl: 'git@github.com:acme/api.git',
    });
    expect(invalidPaths(repository)).toEqual([]);

    const badClone = new RepositoryModel({
      ...minimalRepository(),
      cloneUrl: 'git@github.com:acme/api.git',
    });
    expect(invalidPaths(badClone)).toContain('cloneUrl');

    const badSsh = new RepositoryModel({
      ...minimalRepository(),
      sshUrl: 'https://github.com/acme/api.git',
    });
    expect(invalidPaths(badSsh)).toContain('sshUrl');
  });

  it('caps the topic list', () => {
    const topics = Array.from({ length: 51 }, (_value, index) => `topic-${index}`);
    const repository = new RepositoryModel({ ...minimalRepository(), topics });

    expect(invalidPaths(repository)).toContain('topics');
  });

  it('stores only an installation reference, never a credential', () => {
    const paths = RepositoryModel.schema.paths;
    const credentialLike = Object.keys(paths).filter((path) =>
      /(token|secret|password|privatekey|accesskey)/i.test(path),
    );

    expect(credentialLike).toEqual([]);
    expect(paths.installationId).toBeDefined();
  });

  it('declares a unique index per provider repository', () => {
    const byId = indexNamed(RepositoryModel, 'uniq_provider_repo');
    expect(byId?.key).toBe('provider:1,providerRepoId:1');
    expect(byId?.options.unique).toBe(true);

    const byName = indexNamed(RepositoryModel, 'uniq_provider_full_name');
    expect(byName?.key).toBe('provider:1,fullName:1');
    expect(byName?.options.unique).toBe(true);
  });

  it('indexes the scan scheduler work list', () => {
    const scheduler = indexNamed(RepositoryModel, 'scan_schedule');

    expect(scheduler?.key).toBe('scanEnabled:1,lastScanAt:1');
    expect(scheduler?.options.unique).toBeUndefined();
  });
});
