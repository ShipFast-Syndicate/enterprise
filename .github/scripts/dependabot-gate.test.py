"""Exercise the exact Python embedded in the reusable workflow; no network."""
import copy
import runpy
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/dependabot-merge-gate.yml'
source = WORKFLOW.read_text().split("          python3 - <<'PY'\n", 1)[1].split('          PY\n', 1)[0]
# Load the exact workflow as a temporary test module. run_name keeps its API
# entrypoint inactive; tests supply fixture readers in this unprivileged job.
with tempfile.TemporaryDirectory() as directory:
    module = Path(directory) / 'gate.py'
    module.write_text('\n'.join(line[10:] for line in source.splitlines()))
    namespace = runpy.run_path(str(module), run_name='gate_test')
evaluate = namespace['evaluate']
HEAD = 'a' * 40
REPO = 'ShipFast-Syndicate/example'

class Gate(unittest.TestCase):
    def test_runner_shell_keeps_quoted_python_heredoc(self):
        self.assertIn("        shell: bash\n        run: |\n          python3 - <<'PY'", WORKFLOW.read_text())

    def test_delayed_check_completes_without_bypassing_green(self):
        self.checks.append(self.check(id=2, name='CodeQL', status='in_progress', conclusion=None))
        waits = []
        def finish(seconds):
            waits.append(seconds)
            self.checks[1].update(status='completed', conclusion='success')
        result = namespace['after_ci'](self.reader, REPO, 1, HEAD, apply=True, sleep=finish)
        self.assertTrue(result.startswith('merged:'))
        self.assertEqual(waits, [20])
        self.assertEqual(len(self.writes), 1)

    def test_pending_check_stops_after_bounded_retries(self):
        self.checks.append(self.check(id=2, name='CodeQL', status='in_progress', conclusion=None))
        waits = []
        result = namespace['after_ci'](self.reader, REPO, 1, HEAD, apply=True, sleep=waits.append)
        self.assertTrue(result.startswith('hold:'))
        self.assertEqual(waits, [20] * 6)
        self.assertEqual(self.writes, [])

    def test_head_change_during_wait_never_merges(self):
        self.checks.append(self.check(id=2, name='CodeQL', status='in_progress', conclusion=None))
        def move(seconds):
            self.pr['head']['sha'] = 'b' * 40
            self.checks[1].update(status='completed', conclusion='success')
        self.assertTrue(namespace['after_ci'](self.reader, REPO, 1, HEAD, apply=True, sleep=move).startswith('hold:'))
        self.assertEqual(self.writes, [])

    def test_review_hold_is_not_retried(self):
        self.reviews = [{'id': 1, 'state': 'CHANGES_REQUESTED', 'user': {'login': 'reviewer'}}]
        waits = []
        self.assertEqual(namespace['after_ci'](self.reader, REPO, 1, HEAD, apply=True, sleep=waits.append), 'hold: unresolved requested changes')
        self.assertEqual(waits, [])
        self.assertEqual(self.writes, [])

    def setUp(self):
        self.pr = {'state':'open', 'draft':False, 'user':{'login':'dependabot[bot]','type':'Bot'},
                   'head':{'sha':HEAD,'repo':{'full_name':REPO}}, 'labels':[],
                   'mergeable':True,'mergeable_state':'clean'}
        self.checks = [self.check()]
        self.statuses = []
        self.reviews = []
        self.commits = [{'author':{'login':'dependabot[bot]'},'commit':{'verification':{'verified':True},'message':'bump\n\n---\nupdated-dependencies:\n- dependency-name: example\n  update-type: version-update:semver-patch\n...\n'}}]
        self.writes = []
        self.pr_reads = 0
        self.check_reads = 0
        self.change_pr = None
        self.change_ci = False
        self.merge_response = {'merged':True}

    def check(self, **overrides):
        row = {'id':1,'name':'ci / summary','head_sha':HEAD,'status':'completed','conclusion':'success','app':{'id':15368,'slug':'github-actions'}}
        row.update(overrides)
        return row

    def reader(self, path, method='GET', body=None):
        if method != 'GET':
            self.writes.append((path,method,body))
            return self.merge_response
        if path.endswith('/pulls/1'):
            self.pr_reads += 1
            if self.pr_reads == 2 and self.change_pr:
                self.pr.update(self.change_pr)
            return copy.deepcopy(self.pr)
        if '/check-runs?' in path:
            self.check_reads += 1
            if self.change_ci and self.check_reads == 2:
                self.checks[0]['status'] = 'in_progress'
            return {'check_runs':copy.deepcopy(self.checks)}
        if '/statuses?' in path:
            return copy.deepcopy(self.statuses)
        if '/commits?per_page=1' in path:
            return copy.deepcopy(self.commits)
        if '/reviews?' in path:
            return copy.deepcopy(self.reviews)
        raise AssertionError(path)

    def run_gate(self, apply=True):
        return evaluate(self.reader, REPO, 1, HEAD, apply)

    def held(self):
        self.assertTrue(self.run_gate().startswith('hold:'))
        self.assertEqual(self.writes, [])

    def test_green_writes_exact_sha_once_without_native_auto_merge(self):
        self.assertTrue(self.run_gate().startswith('merged:'))
        self.assertEqual(self.writes, [(f'repos/{REPO}/pulls/1/merge','PUT',{'sha':HEAD,'merge_method':'squash'})])
        self.assertEqual(self.pr_reads, 2)
        self.assertEqual(self.check_reads, 2)

    def test_read_only_never_merges(self):
        self.assertTrue(self.run_gate(False).startswith('eligible:'))
        self.assertEqual(self.writes, [])

    def test_missing_summary_holds(self):
        self.checks = [self.check(name='dedupe / dedupe',conclusion='skipped')]
        self.held()

    def test_pending_failed_skipped_neutral_summary_holds(self):
        for status, conclusion in [('queued',None),('in_progress',None),('completed','failure'),('completed','skipped'),('completed','neutral')]:
            with self.subTest(status=status, conclusion=conclusion):
                self.checks = [self.check(status=status,conclusion=conclusion)]
                self.held()

    def test_old_success_cannot_override_new_pending_or_failed_attempt(self):
        for status, conclusion in [('queued',None),('completed','failure')]:
            self.checks = [self.check(),self.check(id=2,status=status,conclusion=conclusion)]
            self.held()

    def test_new_success_supersedes_old_failure(self):
        self.checks = [self.check(conclusion='failure'),self.check(id=2)]
        self.assertTrue(self.run_gate().startswith('merged:'))

    def test_other_pending_or_failed_job_holds_even_with_old_green_summary(self):
        for status, conclusion in [('queued',None),('completed','failure')]:
            self.checks = [self.check(),self.check(id=2,name='ci / quality',status=status,conclusion=conclusion)]
            self.held()

    def test_running_self_and_deliberately_skipped_non_summary_do_not_deadlock(self):
        self.checks += [self.check(id=2,name='automerge / automerge',status='in_progress',conclusion=None),self.check(id=3,name='ci / migration',conclusion='skipped')]
        self.assertTrue(self.run_gate().startswith('merged:'))

    def test_spoofed_summary_producer_holds(self):
        self.checks = [self.check(app={'id':4,'slug':'other-app'})]
        self.held()

    def test_other_head_check_holds(self):
        self.checks[0]['head_sha'] = 'b' * 40
        self.held()

    def test_trusted_legacy_status_supported(self):
        self.checks = []
        self.statuses = [{'id':1,'context':'ci / summary','state':'success','creator':{'login':'github-actions[bot]','type':'Bot'}}]
        self.assertTrue(self.run_gate().startswith('merged:'))

    def test_untrusted_or_new_pending_legacy_status_holds(self):
        self.checks = []
        self.statuses = [{'id':1,'context':'ci / summary','state':'success','creator':{'login':'other-bot','type':'Bot'}}]
        self.held()
        self.statuses[0]['creator']['login'] = 'github-actions[bot]'
        self.statuses.append(dict(self.statuses[0],id=2,state='pending'))
        self.held()

    def test_head_change_draft_closed_hold_and_unknown_mergeability_hold(self):
        original = copy.deepcopy(self.pr)
        for changes in [{'head':{'sha':'b'*40}}, {'head':{'sha':HEAD,'repo':None}}, {'draft':True}, {'state':'closed'}, {'labels':[{'name':'HOLD'}]}, {'mergeable':None}, {'mergeable_state':'dirty'}, {'user':{'login':'dependabot-fake[bot]','type':'Bot'}}]:
            self.pr = dict(original, **changes)
            self.held()

    def test_head_or_hold_race_before_merge_holds(self):
        for changes in [{'head':{'sha':'b'*40}}, {'labels':[{'name':'do-not-merge'}]}]:
            self.setUp()
            self.change_pr = changes
            self.held()

    def test_ci_race_before_merge_holds(self):
        self.change_ci = True
        self.held()

    def test_requested_changes_hold(self):
        self.reviews = [{'id':1,'state':'CHANGES_REQUESTED','user':{'login':'reviewer'}}]
        self.held()

    def test_api_failure_never_falls_back(self):
        def failed(*args, **kwargs):
            raise OSError('unavailable')
        with self.assertRaises(OSError):
            evaluate(failed, REPO, 1, HEAD, True)
        self.assertEqual(self.writes, [])

    def test_rejected_merge_does_not_retry(self):
        self.merge_response = {'merged':False}
        with self.assertRaises(ValueError):
            self.run_gate()
        self.assertEqual(len(self.writes), 1)

    def test_invalid_identity_fails_before_api(self):
        with self.assertRaises(ValueError):
            evaluate(self.reader, REPO, 1, 'short', True)
        self.assertEqual(self.pr_reads, 0)

    def test_later_pages_and_truncated_pages_fail_closed(self):
        calls = []
        def reader(path):
            calls.append(path)
            return list(range(100)) if 'page=1' == path.split('&')[-1] else ['last']
        self.assertEqual(len(namespace['pages'](reader,'example?x=1')), 101)
        self.assertEqual(len(calls), 2)
        with self.assertRaises(ValueError):
            namespace['pages'](lambda path: list(range(100)), 'example?x=1')


    def test_only_verified_dependabot_commit_metadata_authorizes_update(self):
        for field, value in [('author', None), ('author', {'login':'other-bot'}), ('commit', {'verification':{'verified':False}})]:
            self.setUp()
            self.commits[0][field] = value
            self.held()

    def test_major_unknown_missing_and_mixed_metadata_hold(self):
        original = self.commits[0]['commit']['message']
        for message in [original.replace('semver-patch','semver-major'), original.replace('semver-patch','unknown'), 'no metadata', original.replace('\n...', '\n- dependency-name: another\n...')]:
            self.commits[0]['commit']['message'] = message
            self.held()

    def test_explicit_permitted_major_still_obeys_ci_gate(self):
        self.commits[0]['commit']['message'] = self.commits[0]['commit']['message'].replace('semver-patch','semver-major')
        self.assertTrue(evaluate(self.reader, REPO, 1, HEAD, False, 'version-update:semver-major').startswith('eligible:'))
        self.checks = []
        self.assertTrue(evaluate(self.reader, REPO, 1, HEAD, True, 'version-update:semver-major').startswith('hold:'))
        self.assertEqual(self.writes, [])

    def test_comment_review_does_not_dismiss_requested_changes(self):
        self.reviews = [{'id':1,'state':'CHANGES_REQUESTED','user':{'login':'reviewer'}}, {'id':2,'state':'COMMENTED','user':{'login':'reviewer'}}]
        self.held()

    def test_ci_completion_selects_unique_fresh_same_repository_pr(self):
        run = {'name':'CI','path':'.github/workflows/ci.yml','head_sha':HEAD,'status':'completed','conclusion':'success','repository':{'full_name':REPO}}
        prs = [dict(self.pr, number=1)]
        def reader(path):
            return run if '/actions/runs/' in path else prs
        select = namespace['ci_pull_request']
        self.assertEqual(select(reader, REPO, 99, HEAD), (1, HEAD, None))
        prs[0]['head']['sha'] = 'b'*40
        self.assertIsNone(select(reader, REPO, 99, HEAD))
        prs[0]['head']['sha'] = HEAD
        prs.append(dict(prs[0],number=2))
        self.assertIsNone(select(reader, REPO, 99, HEAD))
        prs[:] = []
        self.assertIsNone(select(reader, REPO, 99, HEAD))

    def test_ci_completion_rejects_spoofed_stale_or_failed_run(self):
        original = {'name':'CI','path':'.github/workflows/ci.yml','head_sha':HEAD,'status':'completed','conclusion':'success','repository':{'full_name':REPO}}
        for changes in [{'name':'other'}, {'path':'.github/workflows/other.yml'}, {'head_sha':'b'*40}, {'conclusion':'failure'}, {'repository':{'full_name':'other/repo'}}, {'status':'in_progress'}]:
            run = dict(original, **changes)
            def reader(path):
                self.assertIn('/actions/runs/', path)
                return run
            self.assertIsNone(namespace['ci_pull_request'](reader, REPO, 99, HEAD))

class AggregatedCI(unittest.TestCase):
    reader = Gate.reader
    check = Gate.check

    def setUp(self):
        Gate.setUp(self)
        self.run_head = 'd' * 40
        self.run_url = f'https://github.com/{REPO}/actions/runs/99'
        self.run = {'name':'CI', 'path':'.github/workflows/ci.yml',
                    'head_sha':self.run_head, 'status':'completed', 'conclusion':'success',
                    'repository':{'full_name':REPO}, 'event':'workflow_run'}
        self.prs = [dict(self.pr, number=1)]
        self.statuses = [{'id':1, 'context':'ci / summary', 'state':'success',
                          'target_url':self.run_url,
                          'creator':{'login':'github-actions[bot]', 'type':'Bot'}}]

    def aggregate_reader(self, path):
        if '/actions/runs/' in path:
            return self.run
        if '/pulls?state=open' in path:
            return self.prs
        if '/statuses?' in path:
            return self.statuses
        raise AssertionError(path)

    def select(self):
        return namespace['ci_pull_request'](self.aggregate_reader, REPO, 99, self.run_head)

    def test_summary_run_resolves_pr_head_instead_of_default_branch_head(self):
        self.assertEqual(self.select(), (1, HEAD, self.run_url))
        self.assertTrue(evaluate(self.reader, REPO, 1, HEAD, True,
                                 summary_run_url=self.run_url).startswith('merged:'))
        self.assertEqual(self.writes[0][2]['sha'], HEAD)

    def test_spoofed_wrong_run_failed_pending_and_superseded_status_hold(self):
        original = copy.deepcopy(self.statuses[0])
        for fields in [{'target_url':self.run_url + '0'}, {'state':'pending'},
                       {'state':'failure'}, {'creator':{'login':'other', 'type':'Bot'}},
                       {'creator':{'login':'github-actions[bot]', 'type':'User'}}]:
            self.statuses = [dict(original, **fields)]
            self.assertIsNone(self.select())
        self.statuses = [original, dict(original, id=2, target_url=self.run_url + '0')]
        self.assertIsNone(self.select())
        self.statuses = []
        self.assertIsNone(self.select())

    def test_named_ci_summary_workflow_binds_the_published_head(self):
        self.run.update(name='CI summary', path='.github/workflows/ci-summary.yml')
        self.assertEqual(self.select(), (1, HEAD, self.run_url))
        self.run['path'] = '.github/workflows/other.yml'
        self.assertIsNone(self.select())

    def test_summary_superseded_on_final_gate_read_holds(self):
        original_reader = self.reader
        reads = 0
        def race_reader(path, method='GET', body=None):
            nonlocal reads
            if '/statuses?' in path:
                reads += 1
                if reads == 3:
                    self.statuses[0]['target_url'] = self.run_url + '0'
            return original_reader(path, method, body)
        result = evaluate(race_reader, REPO, 1, HEAD, True, summary_run_url=self.run_url)
        self.assertTrue(result.startswith('hold:'), result)
        self.assertEqual(self.writes, [])

    def test_summary_binding_race_holds_before_guarded_merge(self):
        self.assertIsNotNone(self.select())
        self.statuses[0]['target_url'] = self.run_url + '0'
        self.assertTrue(evaluate(self.reader, REPO, 1, HEAD, True,
                                summary_run_url=self.run_url).startswith('hold:'))
        self.assertEqual(self.writes, [])

    def test_ambiguous_prs_and_missing_pr_head_hold(self):
        self.prs.append(dict(self.prs[0], number=2))
        self.assertIsNone(self.select())
        self.prs = [dict(self.prs[0], head={'sha':'invalid', 'repo':{'full_name':REPO}})]
        self.assertIsNone(self.select())

if __name__ == '__main__':
    unittest.main()
