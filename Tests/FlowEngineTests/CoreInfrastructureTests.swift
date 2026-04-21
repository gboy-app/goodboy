// Tests for core infrastructure: SecuredBox, FlowEngine states, Flow DSL.
// GoodboyApp defines no Tools — compliance testing is in ProToolsTests.
//
// Run: swift test --filter CoreInfrastructureTests

import Foundation
import Testing
import FlowEngine
@testable import FlowEngine

// MARK: - SecuredBox Tests

@Suite("SecuredBox")
struct SecuredBoxTests {

    @Test("Clear empties the store")
    func testClear() {
        let store = SecuredBox(forTesting: true)
        store.load([
            BoxItem(url: "a.com", username: "u1", password: "p1", extras: [:]),
            BoxItem(url: "b.com", username: "u2", password: "p2", extras: [:])
        ])
        #expect(store.count == 2)

        store.clear()

        #expect(store.isEmpty)
        #expect(store.count == 0)
        #expect(store.items.isEmpty)
    }

    @Test("Load replaces existing contents")
    func testLoadReplaces() {
        let store = SecuredBox(forTesting: true)
        store.load([BoxItem(url: "a.com", username: "u", password: "p", extras: [:])])
        #expect(store.count == 1)

        store.load([
            BoxItem(url: "b.com", username: "u2", password: "p2", extras: [:]),
            BoxItem(url: "c.com", username: "u3", password: "p3", extras: [:])
        ])
        #expect(store.count == 2)
        #expect(store.items[0].url == "b.com")
    }

    @Test("Append adds to existing contents")
    func testAppend() {
        let store = SecuredBox(forTesting: true)
        store.load([BoxItem(url: "a.com", username: "u", password: "p", extras: [:])])
        store.append([BoxItem(url: "b.com", username: "u2", password: "p2", extras: [:])])

        #expect(store.count == 2)
        #expect(store.items[0].url == "a.com")
        #expect(store.items[1].url == "b.com")
    }

    @Test("Summary reflects stored credentials")
    func testSummary() {
        let store = SecuredBox(forTesting: true)
        #expect(store.summary == "Store is empty.")

        store.load([
            BoxItem(url: "a.com", username: "u", password: "p", extras: [:]),
            BoxItem(url: "b.com", username: "u2", password: nil, extras: [:])
        ])
        let summary = store.summary
        #expect(summary.contains("2 credentials"))
        #expect(summary.contains("1 passwords"))
    }

    @Test("Concurrent append and read are thread-safe")
    func testConcurrentAccess() async {
        let store = SecuredBox(forTesting: true)

        await withTaskGroup(of: Void.self) { group in
            // 10 concurrent appends
            for i in 0..<10 {
                group.addTask {
                    store.append([BoxItem(url: "site\(i).com", username: "u\(i)", password: "p\(i)", extras: [:])])
                }
            }
            // Concurrent reads while appending
            for _ in 0..<10 {
                group.addTask {
                    _ = store.count
                    _ = store.items
                    _ = store.isEmpty
                }
            }
        }

        #expect(store.count == 10)
    }
}

// MARK: - FlowState Tests

@Suite("FlowState")
struct FlowStateTests {

    @Test("All flow states exist")
    func testAllStates() {
        let states: [FlowState] = [.idle, .running, .complete, .failed]
        #expect(states.count == 4)
    }

    @Test("FlowState raw values are strings")
    func testRawValues() {
        #expect(FlowState.idle.rawValue == "idle")
        #expect(FlowState.running.rawValue == "running")
        #expect(FlowState.complete.rawValue == "complete")
        #expect(FlowState.failed.rawValue == "failed")
    }
}

