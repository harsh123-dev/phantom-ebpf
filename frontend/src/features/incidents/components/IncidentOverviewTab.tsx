import { useState } from "react";
import type { IncidentDetailResponse, IncidentStatus, IncidentClassification, IncidentUpdateRequest } from "../../../types/phantom";
import { usePhantomClient } from "../../../hooks/usePhantomClient";

interface IncidentOverviewTabProps {
  incident: IncidentDetailResponse;
  onUpdate: (updated: IncidentDetailResponse) => void;
}

export const IncidentOverviewTab = ({ incident, onUpdate }: IncidentOverviewTabProps): JSX.Element => {
  const client = usePhantomClient();
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);

  const [title, setTitle] = useState(incident.report.title);
  const [summary, setSummary] = useState(incident.report.summary);
  const [status, setStatus] = useState<IncidentStatus>(incident.report.status);
  const [classification, setClassification] = useState<IncidentClassification>(incident.report.classification);
  const [tags, setTags] = useState<string[]>(incident.tags || []);
  const [tagInput, setTagInput] = useState("");
  const [notes, setNotes] = useState(incident.resolution_notes || "");

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const request: IncidentUpdateRequest = {
        expected_revision: incident.report.revision,
        title,
        summary,
        status,
        classification,
        tags,
        resolution_notes: notes,
      };
      const updatedReport = await client.updateIncident(incident.report.incident_id, request);
      onUpdate({
        ...incident,
        report: updatedReport,
        tags: tags,
        resolution_notes: notes,
      });
      setEditing(false);
    } catch (err: any) {
      if (err?.code === "CONFLICT" || err?.status === 409 || err?.message?.includes("revision")) {
        setConflict(true);
      } else {
        setError(err instanceof Error ? err.message : "Failed to save incident");
      }
    } finally {
      setSaving(false);
    }
  };

  const addTag = () => {
    if (tagInput.trim() && !tags.includes(tagInput.trim())) {
      setTags([...tags, tagInput.trim()]);
      setTagInput("");
    }
  };

  const removeTag = (tagToRemove: string) => {
    setTags(tags.filter((t) => t !== tagToRemove));
  };

  if (!editing) {
    return (
      <div className="space-y-6 text-black">
        {conflict && (
          <div className="bg-red-50 border-l-4 border-red-500 p-4">
            <p className="text-red-700">
              <strong>Conflict:</strong> This incident was updated by someone else. Please reload the page to see the latest changes.
            </p>
            <button onClick={() => window.location.reload()} className="mt-2 text-sm text-red-600 font-semibold underline">
              Reload Incident
            </button>
          </div>
        )}
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-2xl font-bold">{incident.report.title}</h2>
            <p className="text-sm text-gray-500 mt-1">Revision {incident.report.revision}</p>
          </div>
          <button
            onClick={() => setEditing(true)}
            className="bg-gray-100 hover:bg-gray-200 text-gray-800 font-medium py-1 px-3 rounded shadow-sm text-sm"
          >
            Edit Overview
          </button>
        </div>

        <div className="flex gap-2 mb-4">
          <span className="inline-flex items-center rounded-full bg-blue-100 px-2.5 py-0.5 text-xs font-medium text-blue-800 capitalize">
            Status: {incident.report.status}
          </span>
          <span className="inline-flex items-center rounded-full bg-purple-100 px-2.5 py-0.5 text-xs font-medium text-purple-800 capitalize">
            Class: {incident.report.classification}
          </span>
        </div>

        <div className="bg-gray-50 p-4 rounded border border-gray-200">
          <h3 className="font-semibold text-gray-700 mb-2">Summary</h3>
          <p className="whitespace-pre-wrap">{incident.report.summary || <span className="text-gray-400 italic">No summary provided.</span>}</p>
        </div>

        <div>
          <h3 className="font-semibold text-gray-700 mb-2">Tags</h3>
          {tags.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {tags.map((tag) => (
                <span key={tag} className="inline-flex items-center rounded bg-gray-200 px-2 py-1 text-xs font-medium text-gray-700">
                  {tag}
                </span>
              ))}
            </div>
          ) : (
            <span className="text-gray-400 italic text-sm">No tags</span>
          )}
        </div>

        {incident.report.status === "resolved" && (
          <div className="bg-green-50 p-4 rounded border border-green-200">
            <h3 className="font-semibold text-green-800 mb-2">Resolution Notes</h3>
            <p className="whitespace-pre-wrap text-green-900">{incident.resolution_notes || <span className="italic">No resolution notes.</span>}</p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6 text-black">
      {conflict && (
        <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-6">
          <p className="text-red-700">
            <strong>Conflict:</strong> This incident was updated by someone else. Please reload the page to see the latest changes.
          </p>
          <button type="button" onClick={() => window.location.reload()} className="mt-2 text-sm text-red-600 font-semibold underline">
            Reload Incident
          </button>
        </div>
      )}

      {error && !conflict && (
        <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-6 text-red-700 text-sm">
          {error}
        </div>
      )}

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Title</label>
        <input
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          className="w-full rounded border border-gray-300 p-2 focus:border-blue-500 focus:outline-none"
        />
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as IncidentStatus)}
            className="w-full rounded border border-gray-300 p-2 focus:border-blue-500 focus:outline-none"
          >
            <option value="draft">Draft</option>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="archived">Archived</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Classification</label>
          <select
            value={classification}
            onChange={(e) => setClassification(e.target.value as IncidentClassification)}
            className="w-full rounded border border-gray-300 p-2 focus:border-blue-500 focus:outline-none"
          >
            <option value="untriaged">Untriaged</option>
            <option value="benign">Benign</option>
            <option value="suspicious">Suspicious</option>
            <option value="confirmed">Confirmed</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Summary</label>
        <textarea
          value={summary}
          onChange={(e) => setSummary(e.target.value)}
          rows={4}
          className="w-full rounded border border-gray-300 p-2 focus:border-blue-500 focus:outline-none"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Tags</label>
        <div className="flex flex-wrap gap-2 mb-2">
          {tags.map((tag) => (
            <span key={tag} className="inline-flex items-center rounded bg-blue-100 px-2 py-1 text-xs font-medium text-blue-800">
              {tag}
              <button type="button" onClick={() => removeTag(tag)} className="ml-1 text-blue-600 hover:text-blue-900 font-bold">
                &times;
              </button>
            </span>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            value={tagInput}
            onChange={(e) => setTagInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addTag())}
            placeholder="Add tag..."
            className="rounded border border-gray-300 p-2 flex-1 focus:border-blue-500 focus:outline-none"
          />
          <button type="button" onClick={addTag} className="bg-gray-200 hover:bg-gray-300 px-4 py-2 rounded text-gray-700 font-medium">
            Add
          </button>
        </div>
      </div>

      {status === "resolved" && (
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Resolution Notes</label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            className="w-full rounded border border-gray-300 p-2 focus:border-blue-500 focus:outline-none"
          />
        </div>
      )}

      <div className="flex justify-end gap-3 pt-4 border-t border-gray-200">
        <button
          onClick={() => setEditing(false)}
          disabled={saving}
          className="bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 font-medium py-2 px-4 rounded shadow-sm disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          onClick={handleSave}
          disabled={saving}
          className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded shadow-sm disabled:opacity-50"
        >
          {saving ? "Saving..." : "Save Changes"}
        </button>
      </div>
    </div>
  );
};
